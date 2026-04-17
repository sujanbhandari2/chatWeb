/** Copy plain text; throws if the Clipboard API is unavailable or denied. */
export async function copyTextToClipboard(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}
