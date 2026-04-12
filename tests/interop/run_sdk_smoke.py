import argparse
import base64
import contextlib
import json
import os
import socket
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parents[2]
INTEROP_TARGET_DIR = Path(tempfile.gettempdir()) / "peas-emulator-interop-target"
_BUILT_BINARY = None


def reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def ensure_binary_built(env):
    global _BUILT_BINARY
    if _BUILT_BINARY is not None:
        return _BUILT_BINARY

    build_env = env.copy()
    build_env["CARGO_TARGET_DIR"] = str(INTEROP_TARGET_DIR)
    subprocess.run(
        ["cargo", "build", "--quiet"],
        cwd=ROOT,
        env=build_env,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    binary = INTEROP_TARGET_DIR / "debug" / (
        "peas-emulator.exe" if os.name == "nt" else "peas-emulator"
    )
    _BUILT_BINARY = binary
    return binary


def wait_for_server(server_url, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = requests.get(server_url, timeout=1)
            if response.status_code < 500:
                return
        except requests.RequestException:
            time.sleep(0.5)
    raise RuntimeError("Peas server did not start in time")


@contextlib.contextmanager
def running_server(extra_env=None):
    blobs_dir = tempfile.mkdtemp(prefix="peas-interop-")
    api_port = reserve_port()
    ui_port = reserve_port()
    server_url = f"http://127.0.0.1:{api_port}"
    env = os.environ.copy()
    env["BLOBS_PATH"] = blobs_dir
    env["API_PORT"] = str(api_port)
    env["UI_PORT"] = str(ui_port)
    env.setdefault("RUST_LOG", "warn")
    if extra_env:
        env.update(extra_env)
    binary_path = ensure_binary_built(env)
    process = subprocess.Popen(
        [str(binary_path)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_server(server_url)
        yield server_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        shutil.rmtree(blobs_dir, ignore_errors=True)


def run_s3_smoke(server_url):
    import boto3
    from botocore.config import Config

    client = boto3.client(
        "s3",
        endpoint_url=server_url,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(s3={"addressing_style": "path"}),
    )
    bucket = "interop-s3"
    client.create_bucket(Bucket=bucket)
    client.put_object(Bucket=bucket, Key="hello.txt", Body=b"s3 smoke")
    client.put_bucket_versioning(
        Bucket=bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )
    client.put_object(Bucket=bucket, Key="versioned.txt", Body=b"v1")
    client.put_object(Bucket=bucket, Key="versioned.txt", Body=b"v2")
    multipart = client.create_multipart_upload(Bucket=bucket, Key="multipart.txt")
    part_one = client.upload_part(
        Bucket=bucket,
        Key="multipart.txt",
        UploadId=multipart["UploadId"],
        PartNumber=1,
        Body=b"multi",
    )
    part_two = client.upload_part(
        Bucket=bucket,
        Key="multipart.txt",
        UploadId=multipart["UploadId"],
        PartNumber=2,
        Body=b"part",
    )
    client.complete_multipart_upload(
        Bucket=bucket,
        Key="multipart.txt",
        UploadId=multipart["UploadId"],
        MultipartUpload={
            "Parts": [
                {"ETag": part_one["ETag"], "PartNumber": 1},
                {"ETag": part_two["ETag"], "PartNumber": 2},
            ]
        },
    )
    body = client.get_object(Bucket=bucket, Key="hello.txt")["Body"].read()
    assert body == b"s3 smoke"
    ranged = client.get_object(Bucket=bucket, Key="hello.txt", Range="bytes=0-1")["Body"].read()
    assert ranged == b"s3"
    keys = [item["Key"] for item in client.list_objects_v2(Bucket=bucket).get("Contents", [])]
    assert "hello.txt" in keys
    prefixed = client.list_objects_v2(Bucket=bucket, Prefix="multi")["Contents"]
    assert any(item["Key"] == "multipart.txt" for item in prefixed)
    versions = client.list_object_versions(Bucket=bucket, Prefix="versioned.txt")
    assert len(versions.get("Versions", [])) >= 2
    multipart_body = client.get_object(Bucket=bucket, Key="multipart.txt")["Body"].read()
    assert multipart_body == b"multipart"


def run_azure_smoke(server_url):
    from datetime import datetime, timedelta, timezone

    from azure.core.credentials import AzureNamedKeyCredential
    from azure.storage.blob import BlobServiceClient, ImmutabilityPolicy

    credential = AzureNamedKeyCredential(
        "devstoreaccount1",
        base64.b64encode(b"topsecretkey").decode("ascii"),
    )
    service = BlobServiceClient(
        account_url=f"{server_url}/devstoreaccount1",
        credential=credential,
    )
    container = "interop-azure"
    service.create_container(container)
    blob = service.get_blob_client(container=container, blob="hello.txt")
    blob.upload_blob(b"azure smoke", overwrite=True, metadata={"owner": "sdk"})
    downloaded = blob.download_blob().readall()
    assert downloaded == b"azure smoke"
    ranged = blob.download_blob(offset=0, length=5).readall()
    assert ranged == b"azure"
    props = blob.get_blob_properties()
    assert props.metadata.get("owner") == "sdk"
    containers = [entry["name"] for entry in service.list_containers(name_starts_with="interop-")]
    assert container in containers
    names = [entry["name"] for entry in service.get_container_client(container).list_blobs(name_starts_with="hell")]
    assert "hello.txt" in names

    append_blob = service.get_blob_client(container=container, blob="events.log")
    append_blob.create_append_blob()
    append_blob.append_block(b"hello ")
    append_blob.append_block(b"azure")
    assert append_blob.download_blob().readall() == b"hello azure"
    append_props = append_blob.get_blob_properties()
    assert append_props.blob_type == "AppendBlob"

    page_blob = service.get_blob_client(container=container, blob="page.bin")
    page_blob.create_page_blob(size=512)
    page_blob.upload_page(b"b" * 512, offset=0, length=512)
    assert page_blob.download_blob(offset=0, length=8).readall() == b"bbbbbbbb"
    page_props = page_blob.get_blob_properties()
    assert page_props.blob_type == "PageBlob"

    lease = blob.acquire_lease()
    try:
        try:
            blob.upload_blob(b"should fail", overwrite=True)
            raise AssertionError("lease-protected overwrite should fail without lease id")
        except Exception:
            pass
        blob.upload_blob(b"leased update", overwrite=True, lease=lease)
    finally:
        lease.release()

    snapshot = blob.create_snapshot()["snapshot"]
    snapshot_blob = service.get_blob_client(
        container=container,
        blob="hello.txt",
        snapshot=snapshot,
    )
    assert snapshot_blob.download_blob().readall() == b"leased update"

    blob.set_immutability_policy(
        ImmutabilityPolicy(
            expiry_time=datetime.now(timezone.utc) + timedelta(days=1),
            policy_mode="Unlocked",
        )
    )
    blob.set_legal_hold(True)
    try:
        blob.delete_blob()
        raise AssertionError("immutable blob delete should fail")
    except Exception:
        pass


def run_gcs_smoke(server_url):
    os.environ["STORAGE_EMULATOR_HOST"] = server_url
    from google.cloud import storage

    client = storage.Client(project="peas-test")
    bucket = client.bucket("interop-gcs")
    client.create_bucket(bucket)
    blob = bucket.blob("hello.txt")
    blob.chunk_size = 256 * 1024
    blob.metadata = {"owner": "sdk"}
    blob.upload_from_string("gcs smoke")
    text = blob.download_as_text()
    assert text == "gcs smoke"
    ranged = blob.download_as_bytes(start=0, end=2)
    assert ranged == b"gcs"
    fetched = bucket.get_blob("hello.txt")
    assert fetched.metadata.get("owner") == "sdk"
    first_generation = fetched.generation
    first_metageneration = fetched.metageneration
    blob.upload_from_string("gcs smoke v2")
    fetched = bucket.get_blob("hello.txt")
    assert fetched.generation != first_generation
    fetched.metadata = {"owner": "sdk2"}
    fetched.patch(if_metageneration_match=fetched.metageneration)
    fetched.reload()
    assert fetched.metadata.get("owner") == "sdk2"
    assert fetched.metageneration != first_metageneration
    names = [item.name for item in client.list_blobs(bucket, prefix="hell")]
    assert "hello.txt" in names


def run_oci_smoke(server_url):
    import oci
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from oci.object_storage import ObjectStorageClient
    from oci.object_storage.models import (
        CommitMultipartUploadDetails,
        CommitMultipartUploadPartDetails,
        CreateBucketDetails,
        CreateMultipartUploadDetails,
    )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    tenancy = "ocid1.tenancy.oc1..aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggg"
    user = "ocid1.user.oc1..aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggg"
    fingerprint = "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"
    config = {
        "user": user,
        "key_file": "unused",
        "fingerprint": fingerprint,
        "tenancy": tenancy,
        "region": "us-ashburn-1",
    }
    signer = oci.signer.Signer(
        tenancy,
        user,
        fingerprint,
        "unused",
        private_key_content=private_key,
    )
    client = ObjectStorageClient(
        config,
        signer=signer,
        service_endpoint=server_url,
    )

    namespace = client.get_namespace().data
    client.create_bucket(
        namespace,
        CreateBucketDetails(name="interop-oci", compartment_id=tenancy),
    )
    client.put_object(
        namespace,
        "interop-oci",
        "hello.txt",
        b"oci smoke",
        opc_meta={"owner": "sdk"},
    )
    response = client.get_object(namespace, "interop-oci", "hello.txt")
    assert response.data.content == b"oci smoke"
    ranged = client.get_object(namespace, "interop-oci", "hello.txt", range="bytes=0-2")
    assert ranged.data.content == b"oci"
    head = client.head_object(namespace, "interop-oci", "hello.txt")
    assert head.headers.get("opc-meta-owner") == "sdk"
    listed = client.list_objects(namespace, "interop-oci", prefix="hell")
    assert any(item.name == "hello.txt" for item in listed.data.objects)

    multipart = client.create_multipart_upload(
        namespace,
        "interop-oci",
        CreateMultipartUploadDetails(
            object="multi.txt",
            content_type="text/plain",
            metadata={"owner": "sdk"},
            storage_tier="InfrequentAccess",
        ),
    ).data
    part_one = client.upload_part(
        namespace,
        "interop-oci",
        "multi.txt",
        multipart.upload_id,
        1,
        b"multi",
    )
    part_two = client.upload_part(
        namespace,
        "interop-oci",
        "multi.txt",
        multipart.upload_id,
        2,
        b"part",
    )
    client.commit_multipart_upload(
        namespace,
        "interop-oci",
        "multi.txt",
        multipart.upload_id,
        CommitMultipartUploadDetails(
            parts_to_commit=[
                CommitMultipartUploadPartDetails(
                    part_num=1, etag=part_one.headers["etag"]
                ),
                CommitMultipartUploadPartDetails(
                    part_num=2, etag=part_two.headers["etag"]
                ),
            ]
        ),
    )
    multi = client.get_object(namespace, "interop-oci", "multi.txt")
    assert multi.data.content == b"multipart"
    multi_head = client.head_object(namespace, "interop-oci", "multi.txt")
    assert multi_head.headers.get("opc-meta-owner") == "sdk"


def run_s3_auth_failure(server_url):
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError

    bad_client = boto3.client(
        "s3",
        endpoint_url=server_url,
        region_name="us-east-1",
        aws_access_key_id="wrong-key",
        aws_secret_access_key="wrong-secret",
        config=Config(s3={"addressing_style": "path"}),
    )
    try:
        bad_client.list_buckets()
    except ClientError as exc:
        assert exc.response["ResponseMetadata"]["HTTPStatusCode"] in (403, 401)
        return
    raise AssertionError("Expected S3 auth failure")


def run_azure_auth_failure(server_url):
    from azure.core.exceptions import HttpResponseError
    from azure.core.credentials import AzureNamedKeyCredential
    from azure.storage.blob import BlobServiceClient

    service = BlobServiceClient(
        account_url=f"{server_url}/devstoreaccount1",
        credential=AzureNamedKeyCredential("devstoreaccount1", base64.b64encode(b"wrong-key").decode("ascii")),
    )
    try:
        list(service.list_containers())
    except HttpResponseError as exc:
        assert exc.status_code in (403, 401)
        return
    raise AssertionError("Expected Azure auth failure")


def run_gcs_auth_failure(server_url):
    signature = requests.get(
        f"{server_url}/missing?GoogleAccessId=wrong-access&Expires=4102444800&Signature=bad",
        timeout=5,
    )
    assert signature.status_code == 403


def run_oci_auth_failure(server_url):
    import oci
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from oci.object_storage import ObjectStorageClient

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    tenancy = "ocid1.tenancy.oc1..aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggg"
    user = "ocid1.user.oc1..aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggg"
    fingerprint = "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"
    config = {
        "user": user,
        "key_file": "unused",
        "fingerprint": fingerprint,
        "tenancy": tenancy,
        "region": "us-ashburn-1",
    }
    signer = oci.signer.Signer(
        tenancy,
        user,
        fingerprint,
        "unused",
        private_key_content=private_key,
    )
    client = ObjectStorageClient(config, signer=signer, service_endpoint=server_url)
    try:
        client.get_namespace()
    except oci.exceptions.ServiceError as exc:
        assert exc.status in (401, 403)
        return
    raise AssertionError("Expected OCI auth failure")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--providers",
        default="s3,azure,gcs,oci",
        help="Comma-separated provider list",
    )
    parser.add_argument(
        "--auth-checks",
        action="store_true",
        help="Run provider auth failure scenarios in isolated server instances",
    )
    args = parser.parse_args()
    providers = [provider.strip() for provider in args.providers.split(",") if provider.strip()]

    with running_server() as server_url:
        for provider in providers:
            if provider == "s3":
                run_s3_smoke(server_url)
            elif provider == "azure":
                run_azure_smoke(server_url)
            elif provider == "gcs":
                run_gcs_smoke(server_url)
            elif provider == "oci":
                run_oci_smoke(server_url)
            else:
                raise ValueError(f"Unknown provider '{provider}'")

    if args.auth_checks:
        with running_server({"ACCESS_KEY_ID": "test", "SECRET_ACCESS_KEY": "test-secret"}) as server_url:
            run_s3_auth_failure(server_url)
            run_gcs_auth_failure(server_url)
        with running_server({"ACCESS_KEY_ID": "azure-auth", "SECRET_ACCESS_KEY": base64.b64encode(b"topsecretkey").decode("ascii")}) as server_url:
            run_azure_auth_failure(server_url)
        with running_server({"ACCESS_KEY_ID": "oci-key", "SECRET_ACCESS_KEY": "oci-secret"}) as server_url:
            run_oci_auth_failure(server_url)

    print(json.dumps({"status": "ok", "providers": providers, "auth_checks": args.auth_checks}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        sys.exit(1)
