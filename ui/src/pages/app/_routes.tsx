import { route } from "@askrjs/askr/router";
import Buckets from "./buckets";
import BucketPage from "./bucket";
import BlobPage from "./blob";

export function registerAppRoutes(): void {
  route("/admin", Buckets);
  route(`/admin/{bucketName}`, (params) => (
    <BucketPage bucketName={params.bucketName ?? ""} />
  ));
  route("/app/{bucketName}/{blobId}", (params) => (
    <BlobPage
      bucketName={params.bucketName ?? ""}
      blobId={params.blobId ?? ""}
    />
  ));
}
