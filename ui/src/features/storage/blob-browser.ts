import type { ObjectInfo as BlobInfo } from '../../adapters/api.g';

export type FolderRow = {
  name: string;
  prefix: string;
};

export function collectBlobBrowserRows(
  items: BlobInfo[],
  pathPrefix: string
): {
  folders: FolderRow[];
  blobs: BlobInfo[];
} {
  const folderMap = new Map<string, FolderRow>();
  const blobs: BlobInfo[] = [];

  for (const blob of items) {
    if (!blob.key.startsWith(pathPrefix)) {
      continue;
    }

    const relativeKey = blob.key.slice(pathPrefix.length);
    if (!relativeKey) {
      continue;
    }

    const slashIndex = relativeKey.indexOf('/');
    if (slashIndex >= 0) {
      const folderName = `${relativeKey.slice(0, slashIndex + 1)}`;
      const nextPrefix = `${pathPrefix}${folderName}`;
      if (!folderMap.has(folderName)) {
        folderMap.set(folderName, {
          name: folderName,
          prefix: nextPrefix,
        });
      }
      continue;
    }

    blobs.push(blob);
  }

  const folders = Array.from(folderMap.values()).sort((left, right) =>
    left.name.localeCompare(right.name)
  );

  blobs.sort((left, right) => left.key.localeCompare(right.key));
  return { folders, blobs };
}
