import { describe, expect, it } from "vitest";
import {
  collapseWhitespace,
  decodeEntities,
  extractDraftCandidateNames,
  stripHtmlToText,
} from "../src/text-extract.js";

describe("text-extract: collapseWhitespace", () => {
  it("collapses newlines/tabs/runs of spaces into one space and trims", () => {
    expect(collapseWhitespace("  Hello\n\tworld  \n  again  ")).toBe(
      "Hello world again",
    );
  });
});

describe("text-extract: decodeEntities", () => {
  it("decodes the common named entities", () => {
    expect(decodeEntities("Tom &amp; Jerry &mdash; a show")).toBe(
      "Tom & Jerry — a show",
    );
  });

  it("decodes decimal and hex numeric character references", () => {
    expect(decodeEntities("caf&#233;")).toBe("café");
    expect(decodeEntities("caf&#xe9;")).toBe("café");
  });

  it("leaves an unrecognized named entity untouched rather than guessing", () => {
    expect(decodeEntities("&somethingobscure;")).toBe("&somethingobscure;");
  });

  it("gate finding N4: decodes the full HTML5 named-entity table, not just a hand-picked subset", () => {
    expect(decodeEntities("caf&eacute;")).toBe("café");
    expect(decodeEntities("soft&shy;hyphen")).toContain("hyphen");
  });
});

describe("text-extract: stripHtmlToText (Addendum G: tags stripped, whitespace collapsed)", () => {
  it("strips tags and collapses whitespace", () => {
    const html = `<html><body>
      <h1>Tennessee Golf Trail</h1>
      <p>Nine   courses  make up the Trail.</p>
    </body></html>`;
    expect(stripHtmlToText(html)).toBe(
      "Tennessee Golf Trail Nine courses make up the Trail.",
    );
  });

  it("removes <script>/<style>/<noscript>/<template> blocks entirely, including their text content", () => {
    const html = `<p>Real prose.</p><script>var x = "not prose, ignore me";</script>` +
      `<style>.a { color: red; /* not prose */ }</style>` +
      `<noscript>Enable JS to read this fallback text.</noscript>`;
    const text = stripHtmlToText(html);
    expect(text).toBe("Real prose.");
    expect(text).not.toContain("not prose");
    expect(text).not.toContain("Enable JS");
  });

  it("strips HTML comments", () => {
    expect(stripHtmlToText("<p>Before<!-- a hidden comment -->After</p>")).toBe(
      "Before After",
    );
  });

  it("preserves a quote's exact wording so x2-verdict can find it verbatim after whitespace collapsing", () => {
    const html = `<p>The Robert Trent Jones Golf Trail
      is played year-round across Alabama.</p>`;
    const text = stripHtmlToText(html);
    expect(text).toContain(
      "The Robert Trent Jones Golf Trail is played year-round across Alabama.",
    );
  });

  it("gate finding S4: an inline element boundary (a/span/b/i/em/strong/small/sup/sub/abbr/code/mark/u) inserts NO space, matching a browser's own copy-paste", () => {
    expect(stripHtmlToText("<a>Bear Trace</a>, <a>Fall Creek</a>.")).toBe(
      "Bear Trace, Fall Creek.",
    );
    expect(stripHtmlToText("Sea<b>son</b>")).toBe("Season");
    expect(stripHtmlToText("The trail: Bear Trace<span>, </span>Fall Creek")).toBe(
      "The trail: Bear Trace, Fall Creek",
    );
    expect(stripHtmlToText("caf<sup>1</sup>e")).toBe("caf1e");
  });

  it("gate finding S4: a BLOCK element (p/div/li/br/h1-h6/tr/td) still breaks text", () => {
    expect(stripHtmlToText("<p>One</p><p>Two</p>")).toBe("One Two");
    expect(stripHtmlToText("<li>Bear Trace</li><li>Fall Creek</li>")).toBe(
      "Bear Trace Fall Creek",
    );
    expect(stripHtmlToText("First<br>Second")).toBe("First Second");
  });

  it("gate finding N3: a '>' inside a QUOTED ATTRIBUTE VALUE does not end the tag early", () => {
    const html = `<p>Before <img alt="a > b" src="x.png"> After</p>`;
    const text = stripHtmlToText(html);
    expect(text).toBe("Before After");
    expect(text).not.toContain("b\" src");
  });

  it("gate finding N3: an UNCLOSED <script> drops its source to the end of the document instead of leaking it", () => {
    const html = `<p>Real prose.</p><script>var x = "not prose, no closing tag here`;
    const text = stripHtmlToText(html);
    expect(text).toBe("Real prose.");
    expect(text).not.toContain("not prose");
  });
});

describe("text-extract: extractDraftCandidateNames (DRAFT only — never a confirmation)", () => {
  it("extracts heading text (in document order) then link text (in document order), deduplicated", () => {
    const html = `
      <h1>Tennessee Golf Trail</h1>
      <ul>
        <li><a href="/a">Bear Trace at Harrison Bay</a></li>
        <li><a href="/b">Bear Trace at Ross Creek</a></li>
        <li><a href="/a">Bear Trace at Harrison Bay</a></li>
      </ul>
      <h2>Member Courses</h2>
    `;
    expect(extractDraftCandidateNames(html)).toEqual([
      "Tennessee Golf Trail",
      "Member Courses",
      "Bear Trace at Harrison Bay",
      "Bear Trace at Ross Creek",
    ]);
  });

  it("excludes a heading/link whose collapsed text is too long to plausibly be a course name", () => {
    const longText = "x ".repeat(80).trim();
    const html = `<h1>${longText}</h1><h2>Short Name</h2>`;
    const names = extractDraftCandidateNames(html);
    expect(names).toEqual(["Short Name"]);
  });

  it("ignores script/style content inside headings or near links", () => {
    const html = `<h1>Real Heading<script>evil()</script></h1><a href="#">Link Text</a>`;
    expect(extractDraftCandidateNames(html)).toEqual([
      "Real Heading",
      "Link Text",
    ]);
  });
});
