/* PTECIAL — client-only pentest checklist app. No network, no dependencies. */
(function () {
  "use strict";

  var DATA = window.CHECKLISTS || {};
  var ORDER = ["web", "api"].filter(function (k) { return DATA[k]; })
    .concat(Object.keys(DATA).filter(function (k) { return k !== "web" && k !== "api"; }));

  var LS = {
    theme: "ptecial.theme",
    current: "ptecial.current",
    state: function (id) { return "ptecial.state." + id; } // { checked:{id:true}, notes:{id:str} }
  };

  // ---- element refs ----
  var $ = function (s) { return document.querySelector(s); };
  var elSelect = $("#checklist-select");
  var elSearch = $("#search");
  var elLevel = $("#level-filter");
  var elContent = $("#content");
  var elProgressBar = $("#progress-bar");
  var elProgressLabel = $("#progress-label");
  var elRefNote = $("#ref-note");
  var elHideChecked = $("#hide-checked");
  var elLastSaved = $("#last-saved");
  var elToast = $("#toast");

  var currentId = null;
  var state = { checked: {}, notes: {} };

  // ---- storage helpers (guarded; localStorage may be unavailable) ----
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  function lsDel(k) { try { localStorage.removeItem(k); } catch (e) {} }

  function loadState(id) {
    var raw = lsGet(LS.state(id));
    if (raw) { try { var p = JSON.parse(raw); return { checked: p.checked || {}, notes: p.notes || {} }; } catch (e) {} }
    return { checked: {}, notes: {} };
  }
  function saveState() {
    lsSet(LS.state(currentId), JSON.stringify(state));
    stamp();
  }
  function stamp() {
    var d = new Date();
    elLastSaved.textContent = "saved " + d.toLocaleTimeString();
  }

  // ---- utils ----
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function highlight(text, q) {
    var safe = esc(text);
    if (!q) return safe;
    try {
      var re = new RegExp("(" + q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "ig");
      return safe.replace(re, "<mark>$1</mark>");
    } catch (e) { return safe; }
  }
  function toast(msg) {
    elToast.textContent = msg;
    elToast.classList.add("show");
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { elToast.classList.remove("show"); }, 2200);
  }
  function allItems(cl) {
    var out = [];
    cl.sections.forEach(function (s) { s.items.forEach(function (i) { out.push(i); }); });
    return out;
  }

  // ---- rendering ----
  function render() {
    var cl = DATA[currentId];
    if (!cl) { elContent.innerHTML = '<div class="empty">No checklist loaded.</div>'; return; }

    var q = elSearch.value.trim().toLowerCase();
    var level = elLevel.value;
    var hideChecked = elHideChecked.checked;

    elRefNote.textContent = cl.ref ? "Reference: " + cl.ref : "";

    var html = "";
    var shownTotal = 0;

    cl.sections.forEach(function (sec) {
      var rows = "";
      var shown = 0;
      sec.items.forEach(function (it) {
        if (level !== "all" && it.l !== level) return;
        var isChecked = !!state.checked[it.id];
        if (hideChecked && isChecked) return;
        var hay = (it.t + " " + it.d + " " + it.id).toLowerCase();
        if (q && hay.indexOf(q) === -1) return;
        shown++; shownTotal++;

        var note = state.notes[it.id] || "";
        rows +=
          '<div class="item' + (isChecked ? " checked" : "") + (note ? " has-note" : "") + '" data-id="' + esc(it.id) + '">' +
            '<input type="checkbox"' + (isChecked ? " checked" : "") + ' aria-label="Mark ' + esc(it.id) + '" />' +
            '<div class="item-main">' +
              '<div class="item-titlerow">' +
                '<span class="level ' + it.l + '">' + it.l + '</span>' +
                '<span class="item-title">' + highlight(it.t, q) + '</span>' +
                '<span class="item-id">' + esc(it.id) + '</span>' +
              '</div>' +
              '<div class="item-desc">' + highlight(it.d, q) + '</div>' +
              '<button class="note-toggle" type="button">' + (note ? "Edit note" : "+ Add note") + '</button>' +
              '<div class="note-box' + (note ? "" : "") + '">' +
                '<textarea placeholder="Your notes / evidence for ' + esc(it.id) + '…">' + esc(note) + '</textarea>' +
              '</div>' +
            '</div>' +
          '</div>';
      });

      if (shown === 0) return; // hide empty sections under active filters

      var total = sec.items.length;
      html +=
        '<section class="section" data-sec="' + esc(sec.id) + '">' +
          '<div class="section-head">' +
            '<span class="section-caret">▼</span>' +
            '<h2 class="section-title">' + esc(sec.title) + '</h2>' +
            (sec.wstg && sec.wstg !== "—" ? '<span class="section-tag">' + esc(sec.wstg) + '</span>' : "") +
            '<span class="section-count">' + shown + (shown !== total ? " / " + total : "") + '</span>' +
          '</div>' +
          '<div class="section-body">' + rows + '</div>' +
        '</section>';
    });

    if (shownTotal === 0) {
      html = '<div class="empty">No items match the current search / filter.</div>';
    }
    elContent.innerHTML = html;
    updateProgress();
  }

  function updateProgress() {
    var cl = DATA[currentId];
    var items = allItems(cl);
    var done = items.filter(function (i) { return state.checked[i.id]; }).length;
    var pct = items.length ? Math.round((done / items.length) * 100) : 0;
    elProgressBar.style.width = pct + "%";
    elProgressLabel.textContent = done + " / " + items.length + " (" + pct + "%)";
  }

  // ---- markdown export ----
  function buildMarkdown() {
    var cl = DATA[currentId];
    var lines = [];
    lines.push("# PTECIAL — " + cl.title);
    if (cl.ref) lines.push("_Reference: " + cl.ref + "_");
    lines.push("_Exported: " + new Date().toISOString() + "_");
    var items = allItems(cl);
    var done = items.filter(function (i) { return state.checked[i.id]; }).length;
    lines.push("_Progress: " + done + " / " + items.length + "_");
    lines.push("");

    cl.sections.forEach(function (sec) {
      lines.push("## " + sec.title + (sec.wstg && sec.wstg !== "—" ? " (" + sec.wstg + ")" : ""));
      lines.push("");
      sec.items.forEach(function (it) {
        var box = state.checked[it.id] ? "[x]" : "[ ]";
        lines.push("- " + box + " `" + it.id + "` **" + it.t + "** _(" + it.l + ")_");
        lines.push("  " + it.d);
        var note = (state.notes[it.id] || "").trim();
        if (note) {
          note.split("\n").forEach(function (nl) { lines.push("  > Note: " + nl); });
        }
      });
      lines.push("");
    });
    return lines.join("\n");
  }

  function downloadMarkdown() {
    var md = buildMarkdown();
    var blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "ptecial-" + currentId + "-" + new Date().toISOString().slice(0, 10) + ".md";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    toast("Markdown downloaded");
  }

  // ---- markdown import (round-trips checked state + notes by item ID) ----
  function importMarkdown(text) {
    var cl = DATA[currentId];
    var validIds = {};
    allItems(cl).forEach(function (i) { validIds[i.id] = true; });

    var lines = text.split(/\r?\n/);
    var newChecked = {};
    var newNotes = {};
    var lastId = null;
    var matched = 0;

    var itemRe = /^\s*-\s*\[( |x|X)\]\s*`([^`]+)`/;
    var noteRe = /^\s*>\s*Note:\s?(.*)$/;

    lines.forEach(function (line) {
      var m = itemRe.exec(line);
      if (m) {
        var id = m[2].trim();
        if (validIds[id]) {
          lastId = id;
          matched++;
          if (m[1].toLowerCase() === "x") newChecked[id] = true;
        } else {
          lastId = null;
        }
        return;
      }
      var nm = noteRe.exec(line);
      if (nm && lastId) {
        newNotes[lastId] = (newNotes[lastId] ? newNotes[lastId] + "\n" : "") + nm[1];
      }
    });

    if (matched === 0) {
      toast("No matching items found in file");
      return;
    }
    state.checked = newChecked;
    state.notes = newNotes;
    saveState();
    render();
    toast("Imported " + matched + " items");
  }

  // ---- dropdown population ----
  function populateSelect() {
    elSelect.innerHTML = ORDER.map(function (k) {
      return '<option value="' + esc(k) + '">' + esc(DATA[k].title) + '</option>';
    }).join("");
  }

  function switchChecklist(id) {
    if (!DATA[id]) id = ORDER[0];
    currentId = id;
    elSelect.value = id;
    lsSet(LS.current, id);
    state = loadState(id);
    render();
  }

  // ---- event wiring ----
  function onContentClick(e) {
    var head = e.target.closest(".section-head");
    if (head) { head.parentNode.classList.toggle("collapsed"); return; }

    var noteBtn = e.target.closest(".note-toggle");
    if (noteBtn) {
      var box = noteBtn.nextElementSibling;
      box.classList.toggle("open");
      if (box.classList.contains("open")) box.querySelector("textarea").focus();
      return;
    }
  }
  function onContentChange(e) {
    if (e.target.matches('input[type="checkbox"]')) {
      var id = e.target.closest(".item").getAttribute("data-id");
      if (e.target.checked) state.checked[id] = true; else delete state.checked[id];
      e.target.closest(".item").classList.toggle("checked", e.target.checked);
      saveState();
      updateProgress();
      if (elHideChecked.checked && e.target.checked) render();
    }
  }
  function onContentInput(e) {
    if (e.target.matches(".note-box textarea")) {
      var item = e.target.closest(".item");
      var id = item.getAttribute("data-id");
      var v = e.target.value;
      if (v.trim()) state.notes[id] = v; else delete state.notes[id];
      item.classList.toggle("has-note", !!v.trim());
      saveState();
    }
  }

  function setTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    lsSet(LS.theme, t);
    $("#theme-toggle").textContent = t === "dark" ? "☾" : "☀";
  }

  function init() {
    if (!ORDER.length) { elContent.innerHTML = '<div class="empty">No checklist data found.</div>'; return; }

    setTheme(lsGet(LS.theme) || "dark");
    populateSelect();
    switchChecklist(lsGet(LS.current) || ORDER[0]);

    elSelect.addEventListener("change", function () { switchChecklist(elSelect.value); });
    elSearch.addEventListener("input", render);
    elLevel.addEventListener("change", render);
    elHideChecked.addEventListener("change", render);

    elContent.addEventListener("click", onContentClick);
    elContent.addEventListener("change", onContentChange);
    elContent.addEventListener("input", onContentInput);

    $("#expand-all").addEventListener("click", function () {
      document.querySelectorAll(".section").forEach(function (s) { s.classList.remove("collapsed"); });
    });
    $("#collapse-all").addEventListener("click", function () {
      document.querySelectorAll(".section").forEach(function (s) { s.classList.add("collapsed"); });
    });
    $("#download-md").addEventListener("click", downloadMarkdown);
    $("#import-md").addEventListener("click", function () { $("#import-file").click(); });
    $("#import-file").addEventListener("change", function (e) {
      var f = e.target.files[0];
      if (!f) return;
      var r = new FileReader();
      r.onload = function () { importMarkdown(String(r.result)); };
      r.readAsText(f);
      e.target.value = "";
    });
    $("#reset-progress").addEventListener("click", function () {
      if (!confirm("Reset all checkboxes and notes for the current checklist?")) return;
      state = { checked: {}, notes: {} };
      lsDel(LS.state(currentId));
      render();
      toast("Progress reset");
    });
    $("#theme-toggle").addEventListener("click", function () {
      setTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark");
    });

    // "/" focuses search; Esc clears/blurs
    document.addEventListener("keydown", function (e) {
      if (e.key === "/" && !/^(input|textarea|select)$/i.test(document.activeElement.tagName)) {
        e.preventDefault();
        elSearch.focus();
        elSearch.select();
      } else if (e.key === "Escape" && document.activeElement === elSearch) {
        elSearch.value = "";
        render();
        elSearch.blur();
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else { init(); }
})();
