import BucketModal from '../../components/storage/bucket-modal';
import BucketTable from '../../components/storage/bucket-table';
import StoragePageHeader from '../../components/storage/storage-page-header';

export default function Buckets() {
  return (
    <>
      <StoragePageHeader
        title="Buckets"
        description="Search buckets and open one to browse blobs."
        actions={<BucketModal />}
      />
      <BucketTable />
    </>
  );
}
