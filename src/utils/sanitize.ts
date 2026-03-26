import { JSDOM } from "jsdom";
import createDOMPurify from "dompurify";

const window = new JSDOM("").window;
const DOMPurify = createDOMPurify(window);

// Default configuration for rich text (proposals, etc.)
const RICH_TEXT_CONFIG = {
  ALLOWED_TAGS: [
    "b",
    "i",
    "em",
    "strong",
    "a",
    "p",
    "ul",
    "ol",
    "li",
    "br",
    "span",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
  ],
  ALLOWED_ATTR: ["href", "target", "rel", "class", "style"],
};

/**
 * Sanitizes HTML using DOMPurify. Highly robust against XSS.
 */
export const sanitize = (html: string) => {
  return DOMPurify.sanitize(html, RICH_TEXT_CONFIG);
};

/**
 * Strictly strips ALL tags. Use for plain text fields like standard chat messages.
 */
export const stripTags = (html: string) => {
  return DOMPurify.sanitize(html, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
};
