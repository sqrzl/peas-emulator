import { A } from "@solidjs/router";
import { parseBreadcrumbs } from "../utils/path-utils";

interface BreadcrumbProps {
  bucketName: string;
  currentPath?: string;
}

export function Breadcrumb(props: BreadcrumbProps) {
  const breadcrumbs = () => parseBreadcrumbs(props.currentPath || "");

  return (
    <nav class="flex items-center gap-2 text-sm mb-6 text-gray-700 dark:text-gray-300">
      <A
        href="/buckets"
        class="flex items-center gap-1 text-blue-600 dark:text-blue-400 hover:underline"
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
          <polyline points="9 22 9 12 15 12 15 22" />
        </svg>
        Buckets
      </A>
      <span class="text-gray-400 dark:text-gray-600">/</span>
      <A
        href={`/buckets/${props.bucketName}`}
        class="text-blue-600 dark:text-blue-400 hover:underline"
      >
        {props.bucketName}
      </A>

      {breadcrumbs().map((segment, index) => (
        <>
          <span class="text-gray-400 dark:text-gray-600">/</span>
          {index === breadcrumbs().length - 1 ? (
            <span class="text-gray-700 dark:text-gray-300">{segment.name}</span>
          ) : (
            <A
              href={`/buckets/${props.bucketName}/${segment.path}`}
              class="text-blue-600 dark:text-blue-400 hover:underline"
            >
              {segment.name}
            </A>
          )}
        </>
      ))}
    </nav>
  );
}
