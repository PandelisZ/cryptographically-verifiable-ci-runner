// Animated walkthrough of a vci round trip. Renders into every element with
// class "walkthrough". Plain script, no build step. Autoplays and loops;
// any click on the controls pauses it. Steps toggle SVG groups by
// data-on="a-b" ranges and move the attestation card between places.
(function () {
  var RUNNERS = ["Vitest", "pytest", "Go", "Cargo", "Rails", "RSpec"];
  var STEPS = [
    { t: 2600, h: "<strong>Three places, one repository.</strong> A developer's laptop, an AI agent in a sandbox and the CI runner all push to and fetch from the same git remote. vci adds no server and no database." },
    { t: 2600, h: "<strong>A change is made.</strong> The agent edits <code>app/models/order.rb</code> on a branch. A developer on a laptop goes through exactly the same steps." },
    { t: 3600, h: "<strong>Run with the collector.</strong> <code>vci run spec/models/order_spec.rb</code> runs the test with a collector attached. Every file it read or looked for, every package and every env var is recorded and hashed: 318 inputs, one root hash." },
    { t: 3200, h: "<strong>Sign.</strong> What ran, against which hashes, with which toolchain, by whom: signed with the agent's own SSH key as an in-toto attestation." },
    { t: 3200, h: "<strong>Push through git.</strong> <code>vci push</code> stores the attestation as git-meta metadata on <code>refs/meta/main</code>, next to the branch. If you can <code>git push</code>, you can share it." },
    { t: 3200, h: "<strong>CI fetches, and trusts only the base branch.</strong> On the pull request the action fetches the metadata and reads the accepted keys and the policy from <code>main</code>, never from the PR." },
    { t: 3800, h: "<strong>Verify, then skip.</strong> Signature from an accepted key? Same toolchain? All 318 inputs re-hashed here: same root? All yes, so <span class=\"skip\">SKIP</span>. Everything without a valid attestation <span class=\"run\">runs</span>." },
    { t: 3600, h: "<strong>Any change runs it again.</strong> A later commit edits <code>config/rates.json</code>, which the test had read. The root no longer matches, so CI <span class=\"run\">runs</span> that test. A skip has to be earned every time." },
    { t: 3000, h: "<strong>Same flow for every runner.</strong> Vitest, pytest, Go, Cargo, Rails and RSpec each have an adapter that knows what a unit is and how to observe its inputs. One repository can mix them." }
  ];

  var ICON = {
    laptop: '<path d="M3 5h14v9H3z"/><path d="M1 16h18"/>',
    robot: '<rect x="3" y="6" width="14" height="10" rx="2"/><path d="M10 2v4M7 11h.01M13 11h.01M7 14h6"/>',
    git: '<circle cx="5" cy="5" r="2"/><circle cx="5" cy="15" r="2"/><circle cx="15" cy="8" r="2"/><path d="M5 7v6M15 10c0 3-3 3-10 3"/>',
    server: '<rect x="2" y="3" width="16" height="6" rx="1.5"/><rect x="2" y="11" width="16" height="6" rx="1.5"/><path d="M5 6h.01M5 14h.01"/>'
  };
  function icon(name, x, y, cls) {
    return '<g class="icon' + (cls ? " " + cls : "") + '" transform="translate(' + x + ',' + y + ')">' + ICON[name] + "</g>";
  }

  function svg() {
    var files = ["app/models/order.rb", "spec/factories/orders.rb", "db/schema.rb", "config/rates.json", "Gemfile.lock"];
    var fileRows = files.map(function (f, i) {
      var y = 300 + i * 22;
      return '<g data-file="' + i + '"><rect class="file" x="62" y="' + y + '" width="200" height="18" rx="4"/>' +
        '<text class="mono" x="70" y="' + (y + 13) + '">' + f + '</text></g>';
    }).join("");
    var tests = ["spec/models/order_spec.rb", "spec/requests/orders_spec.rb", "spec/views/invoice_spec.rb", "spec/lib/money_spec.rb"];
    var testRows = tests.map(function (t, i) {
      var y = 236 + i * 30;
      return '<g data-test="' + i + '"><text class="mono" x="676" y="' + (y + 13) + '">' + t + '</text>' +
        '<g class="badge wait" data-badge="' + i + '"><rect x="872" y="' + y + '" width="42" height="18" rx="4"/><text x="893" y="' + (y + 13) + '" text-anchor="middle">…</text></g></g>';
    }).join("");
    var chips = RUNNERS.map(function (r, i) {
      var x = 40 + i * 150;
      return '<g class="chip" data-chip="' + i + '"><rect x="' + x + '" y="470" width="136" height="28" rx="14"/><text x="' + (x + 68) + '" y="488" text-anchor="middle">' + r + '</text></g>';
    }).join("");
    var pushPath = "M286 330 C 330 330, 330 270, 372 270", fetchPath = "M588 270 C 630 270, 630 230, 660 230";
    return '<svg viewBox="0 0 960 520" role="img" aria-labelledby="wt-title"><title id="wt-title">How vci moves a test result from a laptop or agent sandbox to CI</title>' +
      // Laptop
      '<g data-node="laptop"><rect class="node" x="40" y="48" width="246" height="150" rx="12"/>' + icon("laptop", 56, 60) +
      '<text class="title" x="84" y="74">Developer laptop</text>' +
      '<text class="label" x="56" y="96">runs tests, signs with ~/.ssh/id_ed25519</text>' +
      '<rect class="file" x="62" y="112" width="200" height="18" rx="4"/><text class="mono" x="70" y="125">vci run src/cart.test.ts</text>' +
      '<rect class="file" x="62" y="136" width="200" height="18" rx="4"/><text class="mono" x="70" y="149">vci push</text>' +
      '<text class="label" x="56" y="184">same flow as the agent below</text></g>' +
      // Sandbox
      '<g data-node="sandbox"><rect class="node sandbox" x="40" y="214" width="246" height="232" rx="12"/>' + icon("robot", 56, 226) +
      '<text class="title" x="84" y="240">AI agent · sandbox</text>' +
      '<text class="label" x="56" y="262">its own key, listed on main with an expiry</text>' +
      '<g class="fade" data-on="1-8"><text class="mono" x="56" y="284">branch: agent/orders</text></g>' +
      fileRows +
      '<rect class="scan" data-scan x="58" y="296" width="208" height="2" rx="1"/>' +
      '<g class="fade" data-on="2-2"><text class="mono accent" x="56" y="430">318 inputs → root 21ff5d2d…</text></g>' +
      '<g class="fade" data-on="1-1"><circle class="cursor" cx="248" cy="309" r="4"/></g></g>' +
      // Git
      '<g data-node="git"><rect class="node" x="372" y="150" width="216" height="196" rx="12"/>' + icon("git", 388, 162) +
      '<text class="title" x="416" y="176">git remote</text>' +
      '<text class="label" x="388" y="198">GitHub, GitLab, anything</text>' +
      '<rect class="file" x="388" y="214" width="184" height="18" rx="4"/><text class="mono muted" x="396" y="227">refs/heads/main</text>' +
      '<g class="fade" data-on="4-8"><rect class="file hot" x="388" y="238" width="184" height="18" rx="4"/><text class="mono" x="396" y="251">refs/heads/agent/orders</text></g>' +
      '<g class="fade" data-on="4-8"><rect class="file hot" x="388" y="262" width="184" height="18" rx="4"/><text class="mono" x="396" y="275">refs/meta/main</text></g>' +
      '<g class="fade" data-on="4-8"><text class="label" x="388" y="300">attestations are git-meta metadata</text><text class="label" x="388" y="315">on the path of the test they cover</text></g>' +
      '<g class="fade" data-on="5-7"><text class="label accent" x="388" y="336">CI reads policy and keys from main</text></g></g>' +
      // Wires and packets
      '<path class="wire" data-wire="push" d="' + pushPath + '"/>' +
      '<path class="wire" data-wire="fetch" d="' + fetchPath + '"/>' +
      '<circle class="packet" data-packet="push" r="4" style="offset-path: path(\'' + pushPath + '\')"/>' +
      '<circle class="packet" data-packet="fetch" r="4" style="offset-path: path(\'' + fetchPath + '\')"/>' +
      // CI
      '<g data-node="ci"><rect class="node" x="660" y="48" width="260" height="398" rx="12"/>' + icon("server", 676, 60) +
      '<text class="title" x="704" y="74">CI runner</text>' +
      '<text class="label" x="676" y="96">ubuntu-latest · fresh checkout</text>' +
      '<g class="fade" data-on="5-8"><rect class="file" x="676" y="110" width="228" height="18" rx="4"/><text class="mono" x="684" y="123">vci ci --base-ref $BASE</text></g>' +
      '<g class="stagger" data-on="6-8"><text class="mono" x="676" y="156"><tspan class="accent">✓</tspan> signer in main\'s allowed_signers</text>' +
      '<text class="mono" x="676" y="176"><tspan class="accent">✓</tspan> same Ruby, Rails, Gemfile.lock</text>' +
      '<text class="mono" x="676" y="196"><tspan class="accent" data-check>✓</tspan> <tspan data-checktext>318 inputs re-hashed: same root</tspan></text></g>' +
      '<text class="label" x="676" y="226">units in this pull request</text>' +
      testRows +
      '<g class="fade" data-on="6-8"><text class="mono" x="676" y="384" data-summary>1 to skip, 3 to run</text></g>' +
      '<g class="fade" data-on="6-8"><text class="label" x="676" y="406">skipped units never run here;</text><text class="label" x="676" y="421">the audit log names who vouched</text></g></g>' +
      // Attestation card
      '<g class="env" data-env><circle class="ring" data-ring cx="59" cy="20" r="12"/>' +
      '<rect class="card" x="0" y="0" width="118" height="40" rx="8"/>' +
      '<text class="mono" x="10" y="17">attestation</text><text class="label" x="10" y="32">signed · build-agent</text>' +
      '<circle class="seal" cx="100" cy="20" r="9"/><path class="icon active" transform="translate(94,14) scale(.6)" d="M4 9a5 5 0 1 1 10 0v2H4zM2 11h14v8H2z"/></g>' +
      // Runners
      '<text class="label" x="40" y="462">supported test runners</text>' + chips +
      '</svg>';
  }

  var ENV_POS = { sandbox: "translate(150px,404px)", git: "translate(421px,294px)", ci: "translate(786px,142px)" };

  [].forEach.call(document.querySelectorAll(".walkthrough"), function (root) {
    root.innerHTML =
      '<div class="wt-stage">' + svg() +
      '<div class="wt-bar"><div class="wt-progress"></div><div class="wt-row">' +
      '<div class="wt-num">1</div><p class="wt-caption" aria-live="polite"></p>' +
      '<div class="wt-controls"><button type="button" data-prev aria-label="Previous step">‹</button>' +
      '<div class="wt-dots"></div>' +
      '<button type="button" data-next aria-label="Next step">›</button><button type="button" data-play>Pause</button>' +
      '</div></div></div></div>';

    var caption = root.querySelector(".wt-caption"), num = root.querySelector(".wt-num");
    var dots = root.querySelector(".wt-dots"), progress = root.querySelector(".wt-progress");
    var playBtn = root.querySelector("[data-play]");
    var reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    // ?wt-step=N renders one step, still, for screenshots (the README gif).
    var still = /[?&]wt-step=(\d+)/.exec(location.search);
    if (still) { root.classList.add("static"); reduced = true; }
    var step = still ? Math.min(STEPS.length - 1, +still[1]) : 0, timer = null, playing = !reduced, visible = true;

    STEPS.forEach(function (_, i) {
      var d = document.createElement("button");
      d.type = "button"; d.setAttribute("aria-label", "Step " + (i + 1));
      d.onclick = function () { pause(); go(i); };
      dots.appendChild(d);
    });

    function inRange(spec, s) { var p = spec.split("-"); return s >= +p[0] && s <= +p[1]; }
    function restart(el, cls) { el.classList.remove(cls); void el.getBoundingClientRect(); el.classList.add(cls); }

    function render(prev) {
      root.dataset.step = step;
      caption.innerHTML = STEPS[step].h;
      num.textContent = step + 1;
      [].forEach.call(dots.children, function (d, i) {
        if (i === step) d.setAttribute("aria-current", "step"); else d.removeAttribute("aria-current");
      });
      root.querySelector("[data-prev]").disabled = step === 0;
      root.querySelector("[data-next]").disabled = step === STEPS.length - 1;
      [].forEach.call(root.querySelectorAll("[data-on]"), function (el) {
        el.classList.toggle("on", inRange(el.dataset.on, step));
      });
      // Which place is doing the work.
      var active = { 0: null, 1: "sandbox", 2: "sandbox", 3: "sandbox", 4: "git", 5: "ci", 6: "ci", 7: "ci", 8: null }[step];
      [].forEach.call(root.querySelectorAll("[data-node]"), function (n) {
        var on = n.dataset.node === active || (step === 0 && n.dataset.node !== "git") || (step === 8 && false);
        n.querySelector(".node").classList.toggle("active", on);
      });
      // Inputs light up while collecting; rates.json changes at step 7.
      [].forEach.call(root.querySelectorAll("[data-file]"), function (row) {
        var i = +row.dataset.file, f = row.querySelector(".file");
        f.classList.toggle("changed", (i === 0 && step >= 1 && step <= 6) || (i === 3 && step === 7));
        f.classList.toggle("hot", step >= 2 && step <= 6 && i !== 0);
      });
      var scan = root.querySelector("[data-scan]");
      if (step === 2 && prev !== 2) restart(scan, "on"); else if (step !== 2) scan.classList.remove("on");
      // Attestation card and its motion.
      var env = root.querySelector("[data-env]");
      env.classList.toggle("on", step >= 3 && step <= 5);
      env.style.transform = step <= 3 ? ENV_POS.sandbox : step === 4 ? ENV_POS.git : ENV_POS.ci;
      var ring = root.querySelector("[data-ring]");
      if (step === 3 && prev !== 3) restart(ring, "on"); else if (step !== 3) ring.classList.remove("on");
      ["push", "fetch"].forEach(function (w, i) {
        var on = step === 4 + i;
        root.querySelector('[data-wire="' + w + '"]').classList.toggle("live", on);
        var p = root.querySelector('[data-packet="' + w + '"]');
        if (on && prev !== step) restart(p, "go"); else if (!on) p.classList.remove("go");
      });
      // Verdicts.
      [].forEach.call(root.querySelectorAll("[data-badge]"), function (b) {
        var i = +b.dataset.badge, cls = "wait", txt = "…";
        if (step >= 6) { cls = (i === 0 && step !== 7) ? "skip" : "run"; txt = cls.toUpperCase(); }
        var was = b.getAttribute("class");
        b.setAttribute("class", "badge " + cls);
        b.querySelector("text").textContent = txt;
        if (was.indexOf(cls) < 0 && cls !== "wait") { b.style.animationDelay = (0.5 + i * 0.12) + "s"; restart(b, "pop"); }
      });
      var chk = root.querySelector("[data-check]"), chkText = root.querySelector("[data-checktext]");
      chk.textContent = step === 7 ? "✗" : "✓";
      chk.setAttribute("class", step === 7 ? "warn" : "accent");
      chkText.textContent = step === 7 ? "config/rates.json changed: root differs" : "318 inputs re-hashed: same root";
      root.querySelector("[data-summary]").textContent = step === 7 ? "0 to skip, 4 to run" : "1 to skip, 3 to run";
      [].forEach.call(root.querySelectorAll(".chip"), function (c, i) {
        var hot = step === 8 || (step >= 1 && step <= 7 && (i === 4 || i === 5));
        c.classList.toggle("hot", hot);
        if (step === 8 && prev !== 8) { c.style.animationDelay = (i * 0.12) + "s"; restart(c, "wave"); } else if (step !== 8) c.classList.remove("wave");
      });
      // Progress bar for this step.
      progress.classList.remove("run"); progress.style.width = "0";
      if (playing && visible) { progress.style.animationDuration = STEPS[step].t + "ms"; void progress.getBoundingClientRect(); progress.classList.add("run"); }
    }
    function go(i) { var prev = step; step = Math.max(0, Math.min(STEPS.length - 1, i)); render(prev); }
    function schedule() {
      clearTimeout(timer);
      if (!playing || !visible) return;
      timer = setTimeout(function () { go(step === STEPS.length - 1 ? 0 : step + 1); schedule(); }, STEPS[step].t);
    }
    function pause() { playing = false; clearTimeout(timer); playBtn.textContent = "Play"; progress.classList.remove("run"); }
    function play() { playing = true; playBtn.textContent = "Pause"; render(step); schedule(); }
    root.querySelector("[data-prev]").onclick = function () { pause(); go(step - 1); };
    root.querySelector("[data-next]").onclick = function () { pause(); go(step + 1); };
    playBtn.onclick = function () { if (playing) pause(); else { if (step === STEPS.length - 1) step = 0; play(); } };
    root.tabIndex = 0;
    root.addEventListener("keydown", function (e) {
      if (e.key === "ArrowRight") { pause(); go(step + 1); } else if (e.key === "ArrowLeft") { pause(); go(step - 1); } else if (e.key === " ") { e.preventDefault(); playBtn.onclick(); }
    });
    // Run only while on screen; resume where it left off when scrolled back.
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (es) {
        visible = es[0].isIntersecting;
        if (visible) { if (playing) { render(step); schedule(); } } else clearTimeout(timer);
      }, { threshold: 0.25 }).observe(root);
    }
    if (!playing) playBtn.textContent = "Play";
    render(-1); schedule();
  });
})();
