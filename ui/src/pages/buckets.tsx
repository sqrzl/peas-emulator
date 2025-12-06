import { createSignal, createEffect } from "solid-js";
import { A } from "@solidjs/router";
import { ThemeToggle } from "../components/theme-toggle";
import { apiClient, type BucketInfo } from "../adapters";

export function Buckets() {
  const [buckets, setBuckets] = createSignal<BucketInfo[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);

  createEffect(() => {
    const fetchBuckets = async () => {
      try {
        const data = await apiClient.listBuckets();
        setBuckets(data.buckets);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unknown error");
      } finally {
        setLoading(false);
      }
    };

    fetchBuckets();
  });

  return (
    <div class="min-h-screen bg-white dark:bg-gray-900">
      <div class="p-8">
        <div class="flex items-center justify-between mb-6">
          <h1 class="text-3xl font-bold text-gray-900 dark:text-white">
            Buckets
          </h1>
          <ThemeToggle />
        </div>

        {loading() && (
          <p class="text-gray-500 dark:text-gray-400">Loading...</p>
        )}
        {error() && (
          <p class="text-red-500 dark:text-red-400">Error: {error()}</p>
        )}

        {!loading() && buckets().length === 0 && (
          <p class="text-gray-500 dark:text-gray-400">No buckets found</p>
        )}

        {!loading() && buckets().length > 0 && (
          <div class="grid gap-4">
            {buckets().map((bucket) => (
              <A
                href={`/buckets/${bucket.name}`}
                class="p-4 border border-gray-300 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition bg-white dark:bg-gray-800"
              >
                <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
                  {bucket.name}
                </h2>
                <p class="text-sm text-gray-500 dark:text-gray-400">
                  {bucket.created_at}
                </p>
              </A>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
