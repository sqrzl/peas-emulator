import { state } from "@askrjs/askr";
import { Button } from "@askrjs/themes/controls";
import { Inline, Stack } from "@askrjs/themes/layouts";
import BucketModal from "../../components/storage/bucket-modal";
import BucketTable from "../../components/storage/bucket-table";

export default function Buckets() {
  const [reloadKey, setReloadKey] = state(0);

  function refreshBuckets() {
    setReloadKey((value) => value + 1);
  }

  return (
    <Stack gap="4">
      <Inline justify="between" align="center" gap="3" wrap="wrap">
        <Stack gap="1">
          <h1>Buckets</h1>
          <p>All buckets.</p>
        </Stack>
        <Inline gap="2" align="center" wrap="wrap">
          <Button variant="secondary" onPress={refreshBuckets}>
            Refresh
          </Button>
          <BucketModal onCreated={refreshBuckets} />
        </Inline>
      </Inline>

      <BucketTable key={`bucket-table-${reloadKey()}`} reloadKey={reloadKey()} />
    </Stack>
  );
}
