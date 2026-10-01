// Shared chrome for the vci docs: header, sidebar table of contents, pager,
// copy buttons, tabs and the theme toggle. Plain script, no build step.
(function () {
  var REPO = "https://github.com/PandelisZ/cryptographically-verifiable-ci-runner";
  var PAGES = [
    ["index.html", "Overview"],
    ["get-started.html", "Get started"],
    ["adapters.html", "Test runners"],
    ["configuration.html", "Configuration"],
    ["github-actions.html", "GitHub Actions"],
    ["cli.html", "CLI"],
    ["security.html", "How it works"],
  ];
  var here = location.pathname.split("/").pop() || "index.html";
  var root = document.documentElement;

  // Theme: follow the system unless the reader picked one.
  try {
    var saved = localStorage.getItem("vci-theme");
    if (saved) root.dataset.theme = saved;
  } catch (e) {}

  var ICON = {
    logo: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--accent)"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg>',
    theme: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
    menu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>',
    gh: '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"/></svg>',
  };

  var header = document.createElement("header");
  header.className = "site-header";
  header.innerHTML =
    '<a class="brand" href="index.html">' + ICON.logo + "vci</a>" +
    '<nav class="top-nav" aria-label="Main">' +
    PAGES.map(function (p) {
      return '<a href="' + p[0] + '"' + (p[0] === here ? ' aria-current="page"' : "") + ">" + p[1] + "</a>";
    }).join("") +
    "</nav>" +
    '<div class="header-tools">' +
    '<button class="icon-btn" id="theme-btn" aria-label="Switch colour theme">' + ICON.theme + "</button>" +
    '<a class="icon-btn" href="' + REPO + '" aria-label="GitHub repository">' + ICON.gh + "</a>" +
    '<button class="icon-btn menu-btn" id="menu-btn" aria-label="Menu">' + ICON.menu + "</button>" +
    "</div>";
  document.body.prepend(header);

  document.getElementById("theme-btn").onclick = function () {
    var dark = root.dataset.theme
      ? root.dataset.theme === "dark"
      : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("vci-theme", root.dataset.theme); } catch (e) {}
  };
  document.getElementById("menu-btn").onclick = function () {
    header.querySelector(".top-nav").classList.toggle("open");
  };

  var main = document.querySelector("main");

  // Heading ids, anchors and the sidebar table of contents.
  var toc = document.querySelector(".toc");
  var heads = [].slice.call(main.querySelectorAll("h2, h3"));
  var links = [];
  var section = "";
  heads.forEach(function (h) {
    if (!h.id) {
      var id = h.textContent.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
      // Repeated sub-headings ("What is recorded") get their section as a prefix.
      if (document.getElementById(id)) id = section + "-" + id;
      h.id = id;
    }
    if (h.tagName === "H2") section = h.id;
    if (h.closest(".card, .tabs, .steps") && h.tagName === "H3") return;
    if (toc) {
      var a = document.createElement("a");
      a.href = "#" + h.id;
      a.textContent = h.textContent;
      if (h.tagName === "H3") a.className = "sub";
      toc.appendChild(a);
      links.push([h, a]);
    }
    var anchor = document.createElement("a");
    anchor.className = "anchor";
    anchor.href = "#" + h.id;
    anchor.textContent = "#";
    anchor.setAttribute("aria-label", "Link to this section");
    h.appendChild(anchor);
  });
  // Ids are assigned above, after the browser tried to scroll to the hash.
  if (location.hash.length > 1) {
    var target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
    if (target) target.scrollIntoView();
  }
  if (toc && links.length) {
    var spy = function () {
      var current = links[0];
      links.forEach(function (l) {
        if (l[0].getBoundingClientRect().top < 120) current = l;
      });
      links.forEach(function (l) { l[1].classList.toggle("active", l === current); });
    };
    addEventListener("scroll", spy, { passive: true });
    spy();
  }

  // Wide tables scroll on their own.
  [].forEach.call(main.querySelectorAll("table"), function (t) {
    var w = document.createElement("div");
    w.className = "table-wrap";
    t.parentNode.insertBefore(w, t);
    w.appendChild(t);
  });

  // Copy buttons.
  [].forEach.call(document.querySelectorAll("pre"), function (pre) {
    if (pre.dataset.nocopy !== undefined) return;
    var b = document.createElement("button");
    b.className = "copy-btn";
    b.textContent = "Copy";
    b.onclick = function () {
      var text = pre.querySelector("code") ? pre.querySelector("code").innerText : pre.innerText;
      navigator.clipboard.writeText(text.replace(/\n$/, "")).then(function () {
        b.textContent = "Copied";
        setTimeout(function () { b.textContent = "Copy"; }, 1400);
      });
    };
    pre.appendChild(b);
  });

  // Tabs. Groups sharing data-sync switch together and remember the choice.
  [].forEach.call(document.querySelectorAll(".tabs"), function (tabs) {
    var panels = [].filter.call(tabs.children, function (c) { return c.classList.contains("tab-panel"); });
    var list = document.createElement("div");
    list.className = "tab-list";
    list.setAttribute("role", "tablist");
    var select = function (name, store) {
      var found = panels.some(function (p) { return p.dataset.tab === name; });
      if (!found) return;
      panels.forEach(function (p) { p.hidden = p.dataset.tab !== name; });
      [].forEach.call(list.children, function (b) {
        b.setAttribute("aria-selected", b.textContent === name ? "true" : "false");
      });
      if (store && tabs.dataset.sync) {
        try { localStorage.setItem("vci-tab-" + tabs.dataset.sync, name); } catch (e) {}
        [].forEach.call(document.querySelectorAll('.tabs[data-sync="' + tabs.dataset.sync + '"]'), function (other) {
          if (other !== tabs && other.vciSelect) other.vciSelect(name, false);
        });
      }
    };
    tabs.vciSelect = select;
    panels.forEach(function (p) {
      var b = document.createElement("button");
      b.setAttribute("role", "tab");
      b.textContent = p.dataset.tab;
      b.onclick = function () { select(p.dataset.tab, true); };
      list.appendChild(b);
    });
    tabs.prepend(list);
    var initial = panels[0].dataset.tab;
    try {
      var s = tabs.dataset.sync && localStorage.getItem("vci-tab-" + tabs.dataset.sync);
      if (s) initial = s;
    } catch (e) {}
    select(panels[0].dataset.tab, false);
    select(initial, false);
  });

  // Previous / next.
  var idx = PAGES.findIndex(function (p) { return p[0] === here; });
  if (idx > 0 && !document.body.classList.contains("home")) {
    var pager = document.createElement("nav");
    pager.className = "pager";
    var prev = PAGES[idx - 1], next = PAGES[idx + 1];
    pager.innerHTML =
      '<a href="' + prev[0] + '"><span>Previous</span>' + prev[1] + "</a>" +
      (next ? '<a class="next" href="' + next[0] + '"><span>Next</span>' + next[1] + "</a>" : "");
    main.appendChild(pager);
  }

  var footer = document.createElement("footer");
  footer.innerHTML =
    '<div class="inner"><span>vci is licensed under Apache-2.0.</span>' +
    '<span><a href="' + REPO + '">Source on GitHub</a> · <a href="' + REPO + '/blob/main/README.md">Full reference (README)</a></span></div>';
  document.body.appendChild(footer);
})();
