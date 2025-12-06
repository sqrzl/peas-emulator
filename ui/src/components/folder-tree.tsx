import { A } from "@solidjs/router";
import { For } from "solid-js";
import type { HierarchyItem } from "../utils/path-utils";

interface FolderTreeProps {
  bucketName: string;
  items: HierarchyItem[];
  currentPath?: string;
}

function formatFileSize(bytes?: number): string {
  if (!bytes) return "";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  if (bytes < 1024 * 1024 * 1024)
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + " GB";
}

function formatDate(dateString?: string): string {
  if (!dateString) return "";
  const date = new Date(dateString);
  return date.toLocaleDateString() + " " + date.toLocaleTimeString();
}

export function FolderTree(props: FolderTreeProps) {
  return (
    <div class="space-y-1">
      <For each={props.items}>
        {(item) =>
          item.isFolder ? (
            <A
              href={`/buckets/${props.bucketName}/${item.path}`}
              class="flex items-center gap-3 p-3 rounded-lg hover:bg-blue-50 dark:hover:bg-blue-900/20 text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                class="flex-shrink-0"
              >
                <path d="M5 4h4l3 3h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2" />
              </svg>
              <span class="font-medium">{item.name}/</span>
            </A>
          ) : (
            <div class="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                class="text-gray-600 dark:text-gray-400 flex-shrink-0"
              >
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
              </svg>
              <div class="flex-1">
                <div class="font-medium text-gray-900 dark:text-gray-100">
                  {item.name}
                </div>
                <div class="text-xs text-gray-500 dark:text-gray-400 space-x-2">
                  {item.size && <span>{formatFileSize(item.size)}</span>}
                  {item.lastModified && <span>•</span>}
                  {item.lastModified && (
                    <span>{formatDate(item.lastModified)}</span>
                  )}
                </div>
              </div>
              {item.etag && (
                <div class="text-xs text-gray-400 dark:text-gray-500 font-mono">
                  {item.etag.slice(0, 8)}
                </div>
              )}
            </div>
          )
        }
      </For>
    </div>
  );
}
