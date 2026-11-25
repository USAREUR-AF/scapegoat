// Copy buttons, and the first screen's replay. The replay shows a real artifact
// from the tree (a capture, a vector, a recorded session) in the order it lists
// its records; it decides nothing. Reduced motion: stop on one telling frame.
(function () {
  "use strict";
  document.querySelectorAll("button.copy").forEach(function (b) {
    b.addEventListener("click", function () {
      var text = document.getElementById(b.dataset.copy).textContent;
      if (navigator.clipboard) navigator.clipboard.writeText(text).then(function () {
        b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1600);
      });
    });
  });

  // The replay: site/session.json, recorded by site/record.py against the toy
  // simulator. Lines appear at their recorded times, three times faster; the
  // ladder shows the link state each state line moves to.
  var stage = document.getElementById("stage-lines");
  var ladder = document.getElementById("ladder");
  var clock = document.getElementById("stage-clock");
  if (!stage) return;
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce || !window.fetch) return;
  var SPEED = 3, KEEP = 8;
  function pad(s, n) { while (s.length < n) s += " "; return s; }
  function render(l) {
    var el = document.createElement("span");
    if (l.kind === "state") {
      el.className = "st" + (l.level === "warn" ? " warn" : "");
      el.textContent = "== " + l.text;
    } else if (l.kind) {
      el.className = "in";
      el.textContent = "   " + l.text;
    } else {
      el.className = l.dir;
      el.textContent = (l.dir === "tx" ? "-> " : "<- ") + pad(l.name, 10) + " " + l.text.replace(/ ask=\d+ flags=\d+$/, "");
    }
    return el;
  }
  function setState(s) {
    Array.prototype.forEach.call(ladder.children, function (li) { li.classList.toggle("on", li.dataset.s === s); });
  }
  fetch("session.json").then(function (r) { return r.json(); }).then(function (rec) {
    var lines = rec.lines, i = 0, shown = [];
    function clear() { stage.textContent = ""; shown = []; setState("disabled"); }
    function show(l) {
      if (shown.length) stage.appendChild(document.createTextNode("\n"));
      var el = render(l); stage.appendChild(el); shown.push(el);
      while (shown.length > KEEP) {
        var old = shown.shift();
        if (old.nextSibling) stage.removeChild(old.nextSibling);
        stage.removeChild(old);
      }
      if (l.kind === "state") setState(l.text.split(" -> ")[1].split(":")[0]);
      clock.textContent = "t = " + l.t.toFixed(1) + " s";
    }
    function step() {
      if (i >= lines.length) { setTimeout(function () { i = 0; clear(); step(); }, 4000); return; }
      var l = lines[i++];
      show(l);
      var next = i < lines.length ? (lines[i].t - l.t) * 1000 / SPEED : 0;
      setTimeout(step, Math.max(next, 60));
    }
    clear(); step();
  }).catch(function () {});
})();
