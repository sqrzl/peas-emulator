import { useParams } from "@solidjs/router";
import { createSignal, createEffect } from "solid-js";
import { Breadcrumb } from "../components/breadcrumb";
import { FolderTree } from "../components/folder-tree";
import { ThemeToggle } from "../components/theme-toggle";
import { apiClient, type ObjectInfo } from "../adapters";
import { buildHierarchy } from "../utils/path-utils";

export function BucketContents() {
  const params = useParams();
  const [objects, setObjects] = createSignal<ObjectInfo[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);

  createEffect(() => {
    const fetchObjects = async () => {
      try {
        const bucketName = params["bucket-name"];
        if (!bucketName) throw new Error("No bucket name provided");

        const prefix = params["*"] || undefined;
        const data = await apiClient.listObjects(bucketName, prefix);
        setObjects(data.objects);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unknown error");
      } finally {
        setLoading(false);
      }
    };

    fetchObjects();
  });

  const hierarchy = () => buildHierarchy(objects(), params["*"] || "");
  const bucketName = () => params["bucket-name"] || "";

  return (
    <div class="min-h-screen bg-white dark:bg-gray-900">
      <div class="p-8 max-w-6xl">
        <div class="flex items-center justify-between mb-6">
          <h1 class="text-3xl font-bold text-gray-900 dark:text-white">
            {bucketName()}
          </h1>
          <ThemeToggle />
        </div>
        <Breadcrumb bucketName={bucketName()} currentPath={params["*"]} />

        {loading() && (
          <p class="text-gray-500 dark:text-gray-400">Loading...</p>
        )}
        {error() && (
          <p class="text-red-500 dark:text-red-400">Error: {error()}</p>
        )}

        {!loading() && objects().length === 0 && (
          <p class="text-gray-500 dark:text-gray-400">No objects found</p>
        )}

        {!loading() && objects().length > 0 && (
          <FolderTree bucketName={bucketName()} items={hierarchy()} />
        )}
      </div>
    </div>
  );
}
