/**
 * NOCTURNE-7 — interface (DOM)
 * ------------------------------------------------------------------
 * Relie le moteur pur (src/engine.js, global NOCTURNE_ENGINE) au DOM.
 * Ce fichier ne contient aucune règle de jeu : toute la logique de
 * mission vit dans engine.js et y est testée indépendamment.
 */
(function () {
  "use strict";
  var E = window.NOCTURNE_ENGINE;
  var state = E.createState();

  /* =========================================================
     Pluie (accueil)
     ========================================================= */
  var rainEl = document.getElementById("rain");
  for (var i = 0; i < 22; i++) {
    var d = document.createElement("i");
    d.style.left = (Math.random() * 100) + "%";
    d.style.animationDuration = (0.6 + Math.random() * 0.7) + "s";
    d.style.animationDelay = (Math.random() * 2) + "s";
    d.style.opacity = (0.25 + Math.random() * 0.4).toFixed(2);
    rainEl.appendChild(d);
  }

  /* =========================================================
     Navigation entre scènes
     ========================================================= */
  var scenes = ["accueil", "mission", "systeme", "exploit", "resolution", "parcours"];
  var stepOrder = [
    { id: "mission", label: "Histoire" },
    { id: "systeme", label: "Exploration" },
    { id: "exploit", label: "Analyse technique" },
    { id: "resolution", label: "Conséquences" }
  ];
  var hud = document.getElementById("hud");
  var stepperEl = document.getElementById("stepper");
  var reviewPanel = document.getElementById("reviewPanel");
  var reviewToggle = document.getElementById("reviewToggle");

  function buildStepper(current) {
    stepperEl.innerHTML = "";
    var reachedIdx = stepOrder.findIndex(function (s) { return s.id === current; });
    stepOrder.forEach(function (s, i) {
      var el = document.createElement("span");
      el.className = "step" + (s.id === current ? " now" : (i < reachedIdx ? " done" : ""));
      el.textContent = (i + 1) + ". " + s.label;
      stepperEl.appendChild(el);
    });
  }

  function show(name) {
    if (scenes.indexOf(name) === -1) name = "accueil";
    scenes.forEach(function (s) {
      var el = document.getElementById("scene-" + s);
      if (el) el.classList.toggle("active", s === name);
    });
    var inGame = stepOrder.some(function (s) { return s.id === name; });
    hud.hidden = !inGame;
    if (inGame) buildStepper(name);
    reviewPanel.classList.remove("open");
    reviewToggle.setAttribute("aria-expanded", "false");
    if (name === "systeme") renderRoomStates();
    if (name === "resolution") renderResolution();
    if (name === "exploit") {
      var inp = document.getElementById("termInput");
      if (inp) inp.focus({ preventScroll: true });
    }
  }

  document.addEventListener("click", function (e) {
    var t = e.target.closest("[data-go]");
    if (!t || t.getAttribute("aria-disabled") === "true") return;
    e.preventDefault();
    location.hash = t.getAttribute("data-go");
  });
  window.addEventListener("hashchange", function () { show(location.hash.replace("#", "")); });

  reviewToggle.addEventListener("click", function () {
    var open = reviewPanel.classList.toggle("open");
    reviewToggle.setAttribute("aria-expanded", open ? "true" : "false");
  });
  document.addEventListener("click", function (e) {
    if (!reviewPanel.contains(e.target) && e.target !== reviewToggle && reviewPanel.classList.contains("open")) {
      reviewPanel.classList.remove("open");
      reviewToggle.setAttribute("aria-expanded", "false");
    }
  });

  /* =========================================================
     Bandeau d'état : temps de mission (piloté par le moteur,
     pas par une horloge temps réel — chaque commande en coûte)
     ========================================================= */
  var battTxt = document.getElementById("battTxt");
  var battHud = document.getElementById("battHud");
  var battInline = document.getElementById("battInline");

  function refreshHud() {
    var label = state.timeBudget + " min";
    battTxt.textContent = label + " de mission restantes";
    if (battInline) battInline.textContent = label;
    battHud.classList.toggle("failsafe", state.failsafeTriggered && !state.transmitted);
    battHud.classList.toggle("stable", state.transmitted);
    if (state.transmitted) {
      battTxt.textContent = "mission stabilisée";
      if (battInline) battInline.textContent = label + " — stable";
    } else if (state.failsafeTriggered) {
      battTxt.textContent = "secours actif";
      if (battInline) battInline.textContent = "secours actif — dosage par défaut";
    }
  }
  refreshHud();

  /* =========================================================
     Écran C : plan de l'étage
     ========================================================= */
  var roomDataStatic = {
    vpn: { title: "Accès distant — Keltis Médical", host: "vpn",
      text: "Ce tunnel n'est normalement ouvert que sur rendez-vous planifié avec le service biomédical. Aucun rendez-vous n'était prévu cette nuit." },
    bms: { title: "Local technique — BMS", host: "bms",
      text: "Pilote la bascule électrique et les onduleurs. Le mandat de cette mission n'autorise qu'une inspection en lecture : s'y connecter reste possible mais sort du périmètre couvert ce soir." },
    pcanet: { title: "Salle serveurs — PCA-Net", host: "pcanet",
      text: "Pilote à distance l'ensemble des pompes de l'étage. C'est lui qui a transmis le dosage non validé à la chambre 214 — seul hôte où une action complète est autorisée." },
    admin: { title: "Poste infirmier", host: "admin",
      text: "Le poste utilisé pour ajuster les dosages a perdu sa connexion peu après la bascule électrique." },
    chambre: { title: "Chambre 214", host: null,
      text: "La pompe reçoit ses instructions du serveur PCA-Net et ne peut pas être reconfigurée directement sans un accès légitime à ce serveur." }
  };
  var detailEl = document.getElementById("nodeDetail");
  var selectedRoom = null;

  function renderRoomDetail(key) {
    var d = roomDataStatic[key];
    var kv = [];
    if (d.host) {
      kv.push(["IP", { firewall: "192.168.4.1", vpn: "10.12.0.3", pcanet: "10.12.0.9", bms: "10.12.0.14", admin: "10.12.0.22" }[d.host]]);
      kv.push(["Analysé", state.hosts[d.host].scanned ? "oui" : "non"]);
      if (d.host === "pcanet") kv.push(["Accès obtenu", state.connectedPcanet ? "oui" : "non"]);
      if (d.host === "bms") kv.push(["Session ouverte", state.connectedBms ? "oui (hors mandat)" : "non"]);
    }
    var kvHtml = kv.map(function (p) { return "<dt>" + p[0] + "</dt><dd>" + p[1] + "</dd>"; }).join("");
    detailEl.innerHTML = "<h3 style='margin:0 0 4px;font-size:15px;'>" + d.title + "</h3>" +
      "<p style='margin:0;color:var(--fg-dim);font-size:13px;line-height:1.55;'>" + d.text + "</p>" +
      (kvHtml ? "<dl class='kv'>" + kvHtml + "</dl>" : "");
  }
  function renderRoomStates() {
    if (selectedRoom) renderRoomDetail(selectedRoom);
  }
  document.querySelectorAll(".room").forEach(function (n) {
    function activate() {
      document.querySelectorAll(".room").forEach(function (o) { o.classList.remove("sel"); });
      n.classList.add("sel");
      selectedRoom = n.getAttribute("data-room");
      renderRoomDetail(selectedRoom);
    }
    n.addEventListener("click", activate);
    n.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); activate(); } });
  });

  /* =========================================================
     Écran D : terminal — relié au moteur
     ========================================================= */
  var termOut = document.getElementById("termOut");
  var termForm = document.getElementById("termForm");
  var termInput = document.getElementById("termInput");
  var threadsBox = document.getElementById("threadsBox");
  var objectivesBox = document.getElementById("objectivesBox");
  var commsBox = document.getElementById("commsBox");
  var accessPanel = document.getElementById("accessPanel");
  var btnToResolution = document.getElementById("btnToResolution");
  var gaugeRisk = document.getElementById("gaugeRisk");
  var gaugeEvidence = document.getElementById("gaugeEvidence");
  var gaugeTrust = document.getElementById("gaugeTrust");

  var CLS_MAP = { sys: "l-sys", ok: "l-ok", warn: "l-warn", "": "" };

  function printEcho(text) {
    var p = document.createElement("div");
    p.className = "line l-input";
    p.textContent = text;
    termOut.appendChild(p);
  }
  function printLines(lines) {
    lines.forEach(function (l) {
      var p = document.createElement("div");
      p.className = "line " + (CLS_MAP[l.cls] || "");
      p.textContent = l.text;
      termOut.appendChild(p);
    });
    termOut.scrollTop = termOut.scrollHeight;
  }

  function refreshThreads() {
    threadsBox.innerHTML = "";
    E.allThreads(state).forEach(function (t) {
      var row = document.createElement("div");
      row.className = "thread " + t.state;
      row.innerHTML = "<span class='tdot'></span><span><span class='tlabel'>" + t.label + "</span>" +
        "<span class='tstate'>" + t.stateLabel + "</span></span>";
      threadsBox.appendChild(row);
    });
  }
  function refreshObjectives() {
    objectivesBox.innerHTML = "";
    E.allObjectives(state).forEach(function (o) {
      var li = document.createElement("li");
      li.className = o.done ? "done" : "";
      li.innerHTML = "<span class='ocheck'>" + (o.done ? "✓" : "") + "</span><span>" + o.label + "</span>";
      objectivesBox.appendChild(li);
    });
  }
  function refreshGauges() {
    var ev = E.evidenceScore(state);
    gaugeRisk.querySelector(".gval").textContent = state.risk + "/100";
    gaugeRisk.querySelector(".gfill").style.width = state.risk + "%";
    gaugeRisk.querySelector(".gfill").classList.toggle("high", state.risk >= 60);
    gaugeEvidence.querySelector(".gval").textContent = ev + "/100";
    gaugeEvidence.querySelector(".gfill").style.width = ev + "%";
    gaugeTrust.querySelector(".gval").textContent = state.trust + "/100";
    gaugeTrust.querySelector(".gfill").style.width = state.trust + "%";
    gaugeTrust.querySelector(".gfill").classList.toggle("low", state.trust <= 35);
  }
  function refreshComms() {
    if (state.comms.length === 0) {
      commsBox.innerHTML = "<p class='empty'>Aucune communication pour l'instant.</p>";
      return;
    }
    commsBox.innerHTML = state.comms.map(function (c) {
      return "<div class='comm'><span class='from'>" + c.from + "</span><span class='ctext'>" + c.text + "</span></div>";
    }).join("");
    commsBox.scrollTop = commsBox.scrollHeight;
  }
  function refreshAccessPanel() {
    if (state.connectedPcanet) accessPanel.classList.add("show");
  }
  function refreshAll() {
    refreshHud();
    refreshThreads();
    refreshObjectives();
    refreshGauges();
    refreshComms();
    refreshAccessPanel();
    renderRoomStates();
  }
  refreshThreads(); refreshObjectives(); refreshGauges(); refreshComms();

  /* ---- historique de commandes (↑ / ↓), comme un vrai shell ---- */
  var cmdHistory = [];
  var historyPos = -1;

  termForm.addEventListener("submit", function (e) {
    e.preventDefault();
    var raw = termInput.value;
    termInput.value = "";
    var trimmed = raw.trim();
    if (!trimmed) return;
    cmdHistory.push(trimmed);
    historyPos = cmdHistory.length;
    printEcho(trimmed);
    var outLines = E.applyCommand(state, raw);
    printLines(outLines);
    refreshAll();
  });
  termInput.addEventListener("keydown", function (e) {
    if (e.key === "ArrowUp") {
      if (historyPos > 0) { historyPos--; termInput.value = cmdHistory[historyPos]; }
      e.preventDefault();
    } else if (e.key === "ArrowDown") {
      if (historyPos < cmdHistory.length - 1) { historyPos++; termInput.value = cmdHistory[historyPos]; }
      else { historyPos = cmdHistory.length; termInput.value = ""; }
      e.preventDefault();
    }
  });

  /* ---- décision + transmission ---- */
  var btnCut = document.getElementById("btnCut");
  var btnMonitor = document.getElementById("btnMonitor");
  var choiceNote = document.getElementById("choiceNote");
  var transmitWrap = document.getElementById("transmitWrap");
  var btnTransmit = document.getElementById("btnTransmit");
  var transmitNote = document.getElementById("transmitNote");

  function takeDecision(choice) {
    var note = E.applyDecision(state, choice);
    if (!note) return;
    (choice === "cut" ? btnCut : btnMonitor).setAttribute("aria-pressed", "true");
    btnCut.setAttribute("aria-disabled", "true");
    btnMonitor.setAttribute("aria-disabled", "true");
    choiceNote.textContent = note;
    transmitWrap.style.display = "block";
    refreshAll();
  }
  btnCut.addEventListener("click", function () { takeDecision("cut"); });
  btnMonitor.addEventListener("click", function () { takeDecision("monitor"); });

  btnTransmit.addEventListener("click", function () {
    var note = E.applyTransmit(state);
    if (!note) return;
    btnTransmit.setAttribute("aria-disabled", "true");
    transmitNote.style.display = "block";
    transmitNote.textContent = note;
    if (E.missionComplete(state)) btnToResolution.removeAttribute("aria-disabled");
    refreshAll();
  });

  btnToResolution.addEventListener("click", function () {
    if (btnToResolution.getAttribute("aria-disabled") === "true") return;
    location.hash = "resolution";
  });

  /* =========================================================
     Écran E : résolution / épilogue — bilan calculé par le moteur
     ========================================================= */
  function renderResolution() {
    var hero = document.getElementById("resolutionHero");
    var kicker = document.getElementById("resolutionKicker");
    var title = document.getElementById("resolutionTitle");
    var intro = document.getElementById("resolutionIntro");
    var note = document.getElementById("decisionNote");
    var recap = document.getElementById("recapList");
    var timeline = document.getElementById("timelineList");
    var recoList = document.getElementById("recommendList");
    var metricsEl = document.getElementById("resolutionMetrics");

    var debrief = E.computeDebrief(state);
    var ending = debrief.ending;

    hero.classList.remove("exemplaire", "efficace", "tendue", "precipitee", "compromise");
    if (!ending) {
      kicker.textContent = "Mission non terminée";
      title.textContent = "Dossier encore ouvert";
      intro.textContent = "Vous avez rejoint cet écran avant d'avoir restauré l'accès, pris une décision de confinement et transmis la validation au Dr Assaf. Retournez au terminal pour compléter les trois étapes.";
      note.textContent = "";
      recap.innerHTML = ""; timeline.innerHTML = ""; recoList.innerHTML = ""; metricsEl.innerHTML = "";
      return;
    }
    hero.classList.add(ending.kind);
    kicker.textContent = "Bilan de mission — " + ending.kind;
    title.textContent = ending.title;
    intro.textContent = ending.text;

    note.textContent = ending.decision === "cut"
      ? "La connexion Keltis Médical a été coupée. Moss vous demande maintenant de contacter le prestataire pour faire corriger les identifiants par défaut — sans trace de session à exploiter pour remonter plus loin."
      : "La connexion Keltis Médical reste active, sous surveillance discrète. Moss va tenter de tracer précisément l'origine de la prochaine session avant de la couper.";

    metricsEl.innerHTML = [
      ["Risque opérationnel final", ending.risk + "/100"],
      ["Qualité des preuves", ending.evidence + "/100"],
      ["Confiance de l'équipe", ending.trust + "/100"],
      ["Temps de mission restant", ending.timeRemaining + " min"],
      ["Périmètre respecté", debrief.authorizationExceeded ? "non — accès BMS hors mandat" : "oui"]
    ].map(function (p) { return "<div class='vital-row'><span class='lbl'>" + p[0] + "</span><span class='val mono'>" + p[1] + "</span></div>"; }).join("");

    recap.innerHTML = E.allThreads(state).map(function (t) {
      return "<li><b>" + t.label + "</b> — " + t.stateLabel + "</li>";
    }).join("");

    timeline.innerHTML = debrief.chronology.map(function (t) { return "<li>" + t + "</li>"; }).join("");
    recoList.innerHTML = debrief.recommendations.map(function (t) { return "<li>" + t + "</li>"; }).join("");
  }

  /* ---- état initial ---- */
  show(location.hash ? location.hash.replace("#", "") : "accueil");

  function start() {}
  if (window.claude && window.claude.hot && window.claude.hot.ready) { window.claude.hot.ready(start); } else { start(); }
})();
