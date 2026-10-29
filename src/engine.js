/**
 * NOCTURNE-7 — moteur de simulation (mission pilote "Chambre 214")
 * ------------------------------------------------------------------
 * Ce fichier ne touche jamais au DOM. Il modélise :
 *   - un réseau fictif (5 hôtes, services, fichiers, journaux),
 *   - un terminal à commandes réalistes (recon/scan, ls, cat, logs
 *     avec filtre, creds test, connect, conclude, status, hint…),
 *   - un modèle de conséquences à quatre dimensions : temps, risque
 *     opérationnel, qualité de preuve, confiance de l'équipe,
 *   - une notion de mandat : certaines actions restent possibles
 *     mais sortent du périmètre autorisé et ont un coût de confiance,
 *   - des communications d'équipe déclenchées par de vrais
 *     changements d'état (jamais par le seul écoulement du temps),
 *   - un bilan de mission structuré (chronologie, preuves,
 *     hypothèses, recommandations) calculé depuis l'état final.
 *
 * Il s'exécute identiquement dans un navigateur (<script src="engine.js">,
 * expose window.NOCTURNE_ENGINE) et sous Node (require('./engine.js')),
 * ce qui permet de le tester avec `node --test` sans dépendance externe.
 */
(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.NOCTURNE_ENGINE = api;
  }
})(typeof window !== "undefined" ? window : globalThis, function () {
  "use strict";

  var TIME_BUDGET_START = 36; // minutes de mission simulées

  // ---------------------------------------------------------------
  // Contenu de la mission pilote
  // ---------------------------------------------------------------

  var ALIASES = {
    "firewall": "firewall", "pare-feu": "firewall", "192.168.4.1": "firewall",
    "vpn": "vpn", "keltis": "vpn", "10.12.0.3": "vpn",
    "pcanet": "pcanet", "pca-net": "pcanet", "10.12.0.9": "pcanet",
    "bms": "bms", "gtb": "bms", "10.12.0.14": "bms",
    "admin": "admin", "poste-admin": "admin", "infirmerie": "admin", "10.12.0.22": "admin"
  };

  var HOST_IP = { firewall: "192.168.4.1", vpn: "10.12.0.3", pcanet: "10.12.0.9", bms: "10.12.0.14", admin: "10.12.0.22" };

  // Mandat de la Cellule d'Intervention Cyber pour cette mission.
  // Techniquement, rien n'empêche le joueur de dépasser ce périmètre
  // (voir cmdConnect) — mais cela a un coût de confiance et figure
  // dans le bilan final, pas dans un message d'erreur qui bloquerait
  // l'action.
  var AUTHORIZED_HOSTS = { pcanet: true, vpn: "lecture", bms: "lecture", admin: "lecture", firewall: "lecture" };

  var FILES_BY_HOST = {
    pcanet: ["manuel_keltis.txt"],
    bms: ["segmentation_notice.txt", "generator_log.txt"],
    admin: ["maintenance_electrique.txt"],
    firewall: [], vpn: []
  };

  var FILE_CONTENT = {
    "pcanet:manuel_keltis.txt":
      "Manuel d'exploitation — Keltis PCA-Net Manager.\n" +
      "Le compte de maintenance \"tech\" est préconfiguré en usine\n" +
      "(mot de passe initial : keltis2019) pour les interventions à\n" +
      "distance du prestataire. À modifier impérativement après\n" +
      "l'installation.",
    "bms:segmentation_notice.txt":
      "Note d'installation Keltis Médical.\n" +
      "Le boîtier BMS (10.12.0.14) et le serveur PCA-Net (10.12.0.9)\n" +
      "doivent être placés sur deux VLAN distincts (VLAN 20 / VLAN 30)\n" +
      "selon le plan de déploiement. Le prestataire signale que cette\n" +
      "séparation n'a pas été confirmée par l'hôpital à la mise en service.",
    "bms:generator_log.txt":
      "02:01  Session diagnostic onduleur initiée par Keltis Médical\n" +
      "       (conforme au contrat de maintenance).",
    "admin:maintenance_electrique.txt":
      "Rapport technique bâtiment.\n" +
      "Disjoncteur général Q4 déclenché à 01:53 suite à une surcharge\n" +
      "liée au basculement du groupe électrogène. Intervention de la\n" +
      "maintenance du bâtiment en cours. Aucune anomalie réseau\n" +
      "constatée sur ce poste."
  };

  var LOGS_BY_HOST = {
    firewall: ["01:42  Bascule secteur détectée.", "01:58  Connexion sortante autorisée vers Keltis Médical (VPN)."],
    vpn: [
      "01:58  Session de maintenance ouverte — Keltis Médical.",
      "02:01  Trafic vers 10.12.0.14 (BMS) — conforme au contrat.",
      "02:02  Trafic vers 10.12.0.9 (PCA-Net) — hors périmètre contractuel"
    ],
    pcanet: [
      "01:59  Commande infirmière rejetée (session admin déjà ouverte).",
      "02:03  Modification du dosage — session \"tech\", non validée côté soignant"
    ],
    bms: ["01:40  Bascule groupe électrogène — nominale.", "02:01  Connexion maintenance Keltis — diagnostic onduleur (conforme)."],
    admin: ["01:53  Disjoncteur général Q4 déclenché — intervention électrique prévue.", "01:54  Perte de connexion poste infirmier (conséquence directe)."]
  };

  var SCAN_INFO = {
    firewall: ["Filtre le trafic entrant. Aucun port exposé en dehors des règles standard."],
    vpn: ["Tunnel de maintenance établi avec Keltis Médical.", "Connexion active — hors plage prévue"],
    pcanet: ["443/tcp  ouvert — supervision-infirmiere  (app. interne, authentifiée)", "8443/tcp ouvert — keltis-pcanet-mgr v3.2  (interface d'administration)"],
    bms: ["8443/tcp ouvert — keltis-pcanet-mgr v3.2  (même logiciel que PCA-Net)", "102/tcp  ouvert — iec-60870  (protocole industriel, onduleur/groupe électrogène)"],
    admin: ["Hôte injoignable — aucune réponse (probable coupure locale)."]
  };

  var THREAD_LABELS = {
    thread1: "Identifiants de maintenance par défaut sur PCA-Net",
    thread2: "Absence de cloisonnement réseau entre PCA-Net et le BMS",
    thread3: "Hypothèse : poste infirmier compromis"
  };
  // Verdict réellement exact pour chaque piste (sert à juger les conclusions du joueur).
  var THREAD_CORRECT_VERDICT = { thread1: "confirmee", thread2: "confirmee", thread3: "ecartee" };
  var THREAD_REQUIRED_SIGNALS = { thread1: 2, thread2: 2, thread3: 1 };

  var VERDICT_STATE_LABEL = {
    pending: "à vérifier", "en-cours": "indices partiels, à recouper",
    confirmee: "confirmée", ecartee: "écartée",
    premature: "conclusion prématurée — preuves insuffisantes",
    erreur: "conclusion erronée — contredite par les preuves"
  };

  var OBJECTIVE_LABELS = {
    obj1: "Cartographier le réseau de l'étage",
    obj2: "Établir la cause du dosage non validé",
    obj3: "Établir l'absence de cloisonnement réseau",
    obj4: "Statuer correctement sur la piste du poste infirmier",
    obj5: "Obtenir un accès de maintenance légitime sur PCA-Net",
    obj6: "Statuer sur la connexion du prestataire et transmettre au Dr Assaf"
  };

  var ENDING_TEXT = {
    exemplaire: {
      title: "Intervention exemplaire",
      text: "Investigation méthodique, hypothèses correctement établies, risque opérationnel maîtrisé. Le dossier transmis est solide et l'équipe vous fait confiance sur vos conclusions."
    },
    efficace: {
      title: "Intervention maîtrisée, dossier perfectible",
      text: "L'accès a été restauré et la situation stabilisée, mais le dossier transmis laisse des zones d'ombre — certaines conclusions auraient mérité d'être davantage recoupées."
    },
    tendue: {
      title: "Intervention sous tension",
      text: "Le temps de mission s'est réduit plus vite que l'investigation n'a progressé. Le filet de sécurité de la pompe a dû absorber le retard : la situation a fini par être reprise en main, mais plus tard et avec moins de certitude qu'il n'aurait fallu."
    },
    precipitee: {
      title: "Intervention précipitée",
      text: "L'accès a été repris rapidement, mais au prix d'un dossier de preuves trop mince pour être pleinement exploitable : plusieurs conclusions reposent sur des suppositions plutôt que sur des recoupements vérifiés."
    },
    compromise: {
      title: "Intervention compromise",
      text: "Entre les actions à risque et les conclusions hâtives ou erronées, l'équipe n'a plus une confiance suffisante dans le dossier transmis. La situation est stabilisée, mais l'intervention elle-même doit être revue."
    }
  };

  // ---------------------------------------------------------------
  // État
  // ---------------------------------------------------------------

  function createState() {
    return {
      subnetScanned: false,
      hosts: {
        firewall: { known: true, scanned: true },
        vpn: { known: true, scanned: true },
        pcanet: { known: false, scanned: false },
        bms: { known: false, scanned: false },
        admin: { known: false, scanned: false }
      },
      currentHost: null,
      filesRead: {},
      logsRead: {},
      credsFound: false,
      credsValidated: {},      // { pcanet: true, bms: true } — via `creds test` réussi
      connectedPcanet: false,
      connectedBms: false,
      authExceeded: false,     // action hors mandat (connexion BMS)
      threadVerdict: {},       // { thread1: "confirmee" | "ecartee" | "premature" | "erreur" }
      decision: null,          // null | "cut" | "monitor"
      transmitted: false,
      timeBudget: TIME_BUDGET_START,
      risk: 0,
      trust: 50,
      failsafeTriggered: false,
      timeline: [],            // chronologie pour le bilan final
      comms: [],               // communications d'équipe déclenchées par l'état
      eventFired: { firstScan: false, vulnFound: false, timeLow: false, bmsAuth: false, premature: false }
    };
  }

  function resolveHost(token) {
    return ALIASES[token] || null;
  }

  function clamp(v) { return Math.max(0, Math.min(100, v)); }

  function logTimeline(state, text) { state.timeline.push(text); }
  function pushComm(state, from, text) { state.comms.push({ from: from, text: text }); }

  function adjustRisk(state, delta) { state.risk = clamp(state.risk + delta); }
  function adjustTrust(state, delta) { state.trust = clamp(state.trust + delta); }

  function spend(state, minutes) {
    state.timeBudget -= minutes;
    if (state.timeBudget < 0) state.timeBudget = 0;

    // Événement scénarisé : la pression monte une fois, pas en continu.
    if (!state.eventFired.timeLow && state.timeBudget <= 10 && !state.transmitted) {
      state.eventFired.timeLow = true;
      state.timeBudget = Math.max(0, state.timeBudget - 2); // interruption : appel prioritaire ailleurs
      pushComm(state, "Infirmière référente",
        "Le Dr Assaf demande où vous en êtes — la pompe tient, mais pas indéfiniment.");
      logTimeline(state, "Alerte : temps de mission critique, point de situation demandé.");
    }

    if (state.timeBudget <= 0 && !state.transmitted && !state.failsafeTriggered) {
      state.failsafeTriggered = true;
      adjustTrust(state, -5);
      logTimeline(state, "Le filet de sécurité de la pompe s'active (dosage par défaut) — temps de mission épuisé.");
    }
  }

  function out(lines, text, cls) { lines.push({ text: text, cls: cls || "" }); }

  // ---------------------------------------------------------------
  // Preuves — purement dérivées de l'état, jamais stockées à part
  // ---------------------------------------------------------------

  function evidenceSignals(state) {
    return [
      !!state.credsFound,
      !!state.connectedPcanet,
      !!state.filesRead["bms:segmentation_notice.txt"],
      !!state.logsRead.vpn,
      !!state.connectedBms,
      !!state.logsRead.admin,
      !!state.filesRead["admin:maintenance_electrique.txt"]
    ];
  }
  function evidenceScore(state) {
    var sig = evidenceSignals(state);
    var count = sig.filter(Boolean).length;
    return Math.round((count / sig.length) * 100);
  }

  function threadSignalCount(state, id) {
    if (id === "thread1") return (state.credsFound ? 1 : 0) + (state.connectedPcanet ? 1 : 0);
    if (id === "thread2") return (state.filesRead["bms:segmentation_notice.txt"] ? 1 : 0) + (state.logsRead.vpn ? 1 : 0) + (state.connectedBms ? 1 : 0);
    if (id === "thread3") return (state.logsRead.admin ? 1 : 0) + (state.filesRead["admin:maintenance_electrique.txt"] ? 1 : 0);
    return 0;
  }

  function threadState(state, id) {
    var verdict = state.threadVerdict[id];
    if (verdict) return verdict;
    var count = threadSignalCount(state, id);
    if (count > 0) return "en-cours";
    return "pending";
  }

  function allThreads(state) {
    return ["thread1", "thread2", "thread3"].map(function (id) {
      var s = threadState(state, id);
      return { id: id, label: THREAD_LABELS[id], state: s, stateLabel: VERDICT_STATE_LABEL[s] };
    });
  }

  // ---------------------------------------------------------------
  // Commandes
  // ---------------------------------------------------------------

  function cmdRecon(state, lines, targetRaw) {
    var t = (targetRaw || "").toLowerCase();
    if (!t) { out(lines, "Utilisation : recon <cible> — ex. recon 10.12.0.0/24 ou recon pcanet", "warn"); spend(state, 1); return; }
    if (t === "reseau" || t === "10.12.0.0/24" || t === "subnet" || t === "sous-reseau") {
      state.subnetScanned = true;
      state.hosts.pcanet.known = true; state.hosts.bms.known = true; state.hosts.admin.known = true;
      out(lines, "Reconnaissance du sous-réseau 10.12.0.0/24…", "sys");
      out(lines, "Hôtes détectés :", "sys");
      out(lines, "  10.12.0.9   pcanet   (Serveur PCA-Net)");
      out(lines, "  10.12.0.14  bms      (Boîtier BMS — gestion technique du bâtiment)");
      out(lines, "  10.12.0.22  admin    (Poste infirmier)");
      logTimeline(state, "Cartographie du sous-réseau 10.12.0.0/24.");
      spend(state, 2);
      if (!state.eventFired.firstScan) {
        state.eventFired.firstScan = true;
        pushComm(state, "Moss",
          "Cartographie reçue. Priorité à PCA-Net — c'est lui qui pilote la pompe de la 214.");
      }
      return;
    }
    var key = resolveHost(t);
    if (!key) { out(lines, "Cible inconnue : \"" + targetRaw + "\". Essayez : hosts", "warn"); spend(state, 1); return; }
    if (!state.hosts[key].known) { out(lines, "Hôte non découvert. Lancez d'abord : recon 10.12.0.0/24", "warn"); spend(state, 1); return; }
    state.hosts[key].scanned = true;
    state.currentHost = key;
    out(lines, "Reconnaissance de " + key + " (" + HOST_IP[key] + ")…", "sys");
    (SCAN_INFO[key] || []).forEach(function (l) { out(lines, l); });
    logTimeline(state, "Service scanné sur " + key + ".");
    spend(state, 2);
  }

  function cmdHosts(state, lines) {
    out(lines, "Hôtes connus :", "sys");
    Object.keys(state.hosts).forEach(function (k) {
      var h = state.hosts[k];
      if (!h.known) return;
      var mandat = AUTHORIZED_HOSTS[k] === true ? "action autorisée" : "lecture seule autorisée";
      out(lines, "  " + k + "  " + HOST_IP[k] + "  " + (h.scanned ? "analysé" : "non analysé") + "  — " + mandat);
    });
  }

  function cmdLs(state, lines) {
    if (!state.currentHost) { out(lines, "Aucun hôte ciblé. Utilisez : recon <hôte>", "warn"); spend(state, 1); return; }
    var key = state.currentHost;
    var f = FILES_BY_HOST[key] || [];
    if (f.length === 0) { out(lines, "Aucun fichier accessible depuis cet hôte."); spend(state, 1); return; }
    out(lines, "Fichiers disponibles sur " + key + " :", "sys");
    f.forEach(function (name) { out(lines, "  " + name); });
    spend(state, 1);
  }

  function cmdCat(state, lines, fileRaw) {
    if (!state.currentHost) { out(lines, "Aucun hôte ciblé. Utilisez : recon <hôte>", "warn"); spend(state, 1); return; }
    var key = state.currentHost;
    if (!fileRaw) { out(lines, "Utilisation : cat <fichier>", "warn"); spend(state, 1); return; }
    var f = (FILES_BY_HOST[key] || []).filter(function (n) { return n.toLowerCase() === fileRaw.toLowerCase(); })[0];
    if (!f) { out(lines, "Fichier introuvable sur " + key + ". Essayez : ls", "warn"); spend(state, 1); return; }
    state.filesRead[key + ":" + f] = true;
    out(lines, "--- " + f + " ---", "sys");
    FILE_CONTENT[key + ":" + f].split("\n").forEach(function (l) { out(lines, l); });
    if (key === "pcanet" && f === "manuel_keltis.txt") {
      var wasFound = state.credsFound;
      state.credsFound = true;
      logTimeline(state, "Documentation PCA-Net consultée : identifiants de maintenance par défaut découverts.");
      if (!wasFound && !state.eventFired.vulnFound) {
        state.eventFired.vulnFound = true;
        pushComm(state, "Moss",
          "Des identifiants d'usine jamais changés… classique. Vérifiez si ça ouvre vraiment une session avant de conclure.");
      }
    }
    spend(state, 1);
  }

  function cmdLogs(state, lines, filterTerm) {
    if (!state.currentHost) { out(lines, "Aucun hôte ciblé. Utilisez : recon <hôte>", "warn"); spend(state, 1); return; }
    var key = state.currentHost;
    state.logsRead[key] = true;
    var entries = LOGS_BY_HOST[key] || [];
    if (filterTerm) {
      var needle = filterTerm.toLowerCase();
      var filtered = entries.filter(function (l) { return l.toLowerCase().indexOf(needle) !== -1; });
      out(lines, "Journal — " + key + " (filtre : \"" + filterTerm + "\") :", "sys");
      if (filtered.length === 0) out(lines, "Aucune ligne ne correspond à ce filtre.", "warn");
      filtered.forEach(function (l) { out(lines, l); });
    } else {
      out(lines, "Journal — " + key + " :", "sys");
      entries.forEach(function (l) { out(lines, l); });
    }
    logTimeline(state, "Journal consulté sur " + key + (filterTerm ? " (filtre : " + filterTerm + ")" : "") + ".");
    spend(state, 1);
  }

  /** Extrait un hôte explicite en tête de `rest` (s'il n'est pas un flag --xxx). */
  function takeExplicitHost(state, lines, rest) {
    if (rest.length && rest[0].slice(0, 2) !== "--") {
      var key = resolveHost(rest[0].toLowerCase());
      if (!key) { out(lines, "Cible inconnue : \"" + rest[0] + "\".", "warn"); return { error: true, rest: rest }; }
      if (!state.hosts[key].known) { out(lines, "Hôte non découvert. Lancez d'abord : recon 10.12.0.0/24", "warn"); return { error: true, rest: rest }; }
      if (!state.hosts[key].scanned) { out(lines, "Hôte non analysé. Lancez d'abord : recon " + key, "warn"); return { error: true, rest: rest }; }
      state.currentHost = key;
      return { error: false, rest: rest.slice(1) };
    }
    return { error: false, rest: rest };
  }

  function parseUserPass(rest) {
    var user = null, pass = null;
    for (var i = 0; i < rest.length; i++) {
      if (rest[i] === "--user") { user = rest[i + 1]; i++; }
      else if (rest[i] === "--pass") { pass = rest[i + 1]; i++; }
    }
    return { user: user, pass: pass };
  }

  function cmdCreds(state, lines, rest) {
    if (rest[0] !== "test") { out(lines, "Utilisation : creds test <hôte> --user <u> --pass <p>", "warn"); spend(state, 1); return; }
    var picked = takeExplicitHost(state, lines, rest.slice(1));
    if (picked.error) { spend(state, 1); return; }
    if (!state.currentHost) { out(lines, "Aucun hôte ciblé.", "warn"); spend(state, 1); return; }
    var key = state.currentHost;
    if (key !== "pcanet" && key !== "bms") { out(lines, "Ce système ne propose pas d'interface d'authentification testable ici.", "warn"); spend(state, 1); return; }
    var up = parseUserPass(picked.rest);
    if (!up.user || !up.pass) { out(lines, "Utilisation : creds test <hôte> --user <u> --pass <p>", "warn"); spend(state, 1); return; }
    var valid = up.user.toLowerCase() === "tech" && up.pass === "keltis2019";
    if (valid) {
      state.credsValidated[key] = true;
      out(lines, "Identifiants valides sur " + key + " — compte \"tech\" actif, session non ouverte.", "ok");
      logTimeline(state, "Identifiants validés par test (sans ouverture de session) sur " + key + ".");
      adjustRisk(state, 2);
    } else {
      out(lines, "Identifiants invalides sur " + key + ".", "warn");
      adjustRisk(state, 3);
    }
    spend(state, 2);
  }

  function cmdConnect(state, lines, rest) {
    var picked = takeExplicitHost(state, lines, rest);
    if (picked.error) { spend(state, 1); return; }
    if (!state.currentHost) { out(lines, "Aucun hôte ciblé. Utilisez : recon <hôte>", "warn"); spend(state, 1); return; }
    var key = state.currentHost;
    if (key !== "pcanet" && key !== "bms") { out(lines, "Ce système ne propose pas d'authentification exploitable ici.", "warn"); spend(state, 1); return; }
    var up = parseUserPass(picked.rest);
    if (!up.user || !up.pass) { out(lines, "Utilisation : connect <hôte> --user <u> --pass <p>", "warn"); spend(state, 1); return; }

    if (up.user.toLowerCase() === "tech" && up.pass === "keltis2019") {
      var validated = !!state.credsValidated[key];
      if (key === "pcanet") {
        state.connectedPcanet = true;
        out(lines, "Authentification réussie — session de maintenance ouverte sur PCA-Net.", "ok");
        logTimeline(state, "Session de maintenance ouverte sur PCA-Net" + (validated ? " (identifiants préalablement validés)." : " (sans validation préalable)."));
        adjustRisk(state, validated ? 2 : 4);
      } else {
        state.connectedBms = true;
        out(lines, "Authentification réussie sur BMS — les mêmes identifiants fonctionnent ici aussi.", "ok");
        out(lines, "Confirmation : aucune séparation n'empêche la réutilisation entre les deux systèmes.", "warn");
        logTimeline(state, "Session ouverte sur BMS, hors mandat initial de la mission.");
        adjustRisk(state, (validated ? 2 : 4) + 4); // + coût du dépassement de mandat
        if (!state.authExceeded) {
          state.authExceeded = true;
          adjustTrust(state, -5);
          if (!state.eventFired.bmsAuth) {
            state.eventFired.bmsAuth = true;
            pushComm(state, "Moss",
              "Vous êtes entré sur le BMS. Ce n'est pas dans le mandat de ce soir — ça devra figurer tel quel dans le compte rendu.");
          }
        }
      }
      spend(state, 3);
    } else {
      out(lines, "Accès refusé — identifiants invalides.", "warn");
      adjustRisk(state, 5);
      logTimeline(state, "Tentative d'authentification refusée sur " + key + ".");
      spend(state, 3);
    }
  }

  function cmdConclude(state, lines, rest) {
    var id = rest[0];
    var verdict = rest[1];
    if (["thread1", "thread2", "thread3"].indexOf(id) === -1) {
      out(lines, "Utilisation : conclude <thread1|thread2|thread3> <confirmee|ecartee>", "warn"); spend(state, 1); return;
    }
    if (["confirmee", "ecartee"].indexOf(verdict) === -1) {
      out(lines, "Utilisation : conclude " + id + " <confirmee|ecartee>", "warn"); spend(state, 1); return;
    }
    var count = threadSignalCount(state, id);
    var required = THREAD_REQUIRED_SIGNALS[id];
    var correct = THREAD_CORRECT_VERDICT[id];
    var outcome;
    if (count < required) {
      outcome = "premature";
      out(lines, "Conclusion prématurée sur " + id + " : seulement " + count + "/" + required + " éléments de preuve recoupés.", "warn");
      adjustTrust(state, -4);
      adjustRisk(state, 1);
      if (!state.eventFired.premature) {
        state.eventFired.premature = true;
        pushComm(state, "Dr Assaf",
          "Ne concluons rien tant que ce n'est pas recoupé. Je dois pouvoir expliquer chaque ligne du dossier ensuite.");
      }
    } else if (verdict !== correct) {
      outcome = "erreur";
      out(lines, "Conclusion enregistrée (" + verdict + ") — mais elle est contredite par les preuves recueillies.", "warn");
      adjustTrust(state, -6);
      adjustRisk(state, 2);
    } else {
      outcome = verdict;
      out(lines, "Conclusion confirmée par les preuves : " + id + " — " + verdict + ".", "ok");
      adjustTrust(state, 6);
    }
    state.threadVerdict[id] = outcome;
    logTimeline(state, "Conclusion formulée sur " + THREAD_LABELS[id] + " : " + VERDICT_STATE_LABEL[outcome] + ".");
    spend(state, 1);
  }

  function cmdStatus(state, lines) {
    out(lines, "État de l'enquête :", "sys");
    out(lines, "  Sous-réseau analysé : " + (state.subnetScanned ? "oui" : "non"));
    out(lines, "  Hôte ciblé : " + (state.currentHost || "aucun"));
    out(lines, "  Accès PCA-Net : " + (state.connectedPcanet ? "obtenu" : "non obtenu"));
    out(lines, "  Temps de mission restant : " + state.timeBudget + " min");
    out(lines, "  Risque opérationnel : " + state.risk + "/100");
    out(lines, "  Qualité des preuves : " + evidenceScore(state) + "/100");
    out(lines, "  Confiance de l'équipe : " + state.trust + "/100");
  }

  function cmdHint(state, lines) {
    var msg;
    if (!state.subnetScanned) msg = "commencez par une reconnaissance du sous-réseau — recon 10.12.0.0/24";
    else if (!state.currentHost || !state.hosts[state.currentHost].scanned) msg = "ciblez un hôte découvert, par exemple — recon pcanet";
    else if (state.currentHost === "admin" && !state.logsRead.admin) msg = "avant de soupçonner ce poste, vérifiez son journal — logs";
    else if (state.currentHost === "pcanet" && !state.credsFound) msg = "listez puis lisez la documentation du serveur — ls, puis cat manuel_keltis.txt";
    else if (state.credsFound && !state.connectedPcanet) msg = "validez puis tentez l'accès — creds test pcanet --user tech --pass keltis2019, puis connect pcanet --user tech --pass keltis2019";
    else if (state.connectedPcanet && threadState(state, "thread1") === "en-cours") msg = "les preuves sont réunies — formulez votre conclusion : conclude thread1 confirmee";
    else if (state.connectedPcanet && !state.hosts.bms.scanned) msg = "pour comprendre comment cet accès a pu arriver jusqu'ici, analysez aussi le BMS — recon bms (lecture seule recommandée, le mandat ne couvre pas une connexion complète)";
    else msg = "le panneau \"Accès de maintenance obtenu\" à côté du terminal attend une décision sur la connexion du prestataire.";
    out(lines, "Indice : " + msg, "sys");
    spend(state, 2);
  }

  function cmdClear(lines) { out(lines, "Terminal vidé.", "sys"); }

  function cmdHelp(lines) {
    out(lines, "Commandes : help, hosts, recon <cible>, ls, cat <fichier>, logs [--filter <mot>],", "sys");
    out(lines, "            creds test <hôte> --user <u> --pass <p>, connect [<hôte>] --user <u> --pass <p>,", "sys");
    out(lines, "            conclude <threadN> <confirmee|ecartee>, status, hint, clear", "sys");
    out(lines, "Chaque commande consomme du temps de mission et peut influer sur le risque opérationnel.", "sys");
  }

  /**
   * Interprète une ligne de commande et fait évoluer l'état.
   * Retourne les lignes de sortie du terminal ({text, cls}[]).
   * Ne lève jamais d'exception sur une entrée invalide.
   */
  function applyCommand(state, raw) {
    var lines = [];
    var input = (raw || "").trim();
    if (!input) return lines;
    var parts = input.split(/\s+/);
    var cmd = parts[0].toLowerCase();
    var rest = parts.slice(1);
    switch (cmd) {
      case "help": cmdHelp(lines); break;
      case "hosts": cmdHosts(state, lines); break;
      case "recon": case "scan": cmdRecon(state, lines, rest.join(" ")); break;
      case "ls": cmdLs(state, lines); break;
      case "cat": cmdCat(state, lines, rest.join(" ")); break;
      case "logs": {
        var filterTerm = null;
        var fi = rest.indexOf("--filter");
        if (fi !== -1) filterTerm = rest.slice(fi + 1).join(" ");
        cmdLogs(state, lines, filterTerm);
        break;
      }
      case "creds": cmdCreds(state, lines, rest); break;
      case "connect": cmdConnect(state, lines, rest); break;
      case "conclude": cmdConclude(state, lines, rest); break;
      case "status": cmdStatus(state, lines); break;
      case "hint": cmdHint(state, lines); break;
      case "clear": cmdClear(lines); break;
      default:
        out(lines, "Commande inconnue : \"" + cmd + "\". Tapez \"help\" pour la liste des commandes.", "warn");
        spend(state, 1);
    }
    return lines;
  }

  function applyDecision(state, choice) {
    if (state.decision) return null;
    if (choice !== "cut" && choice !== "monitor") return null;
    state.decision = choice;
    if (choice === "cut") {
      adjustRisk(state, -5);
      adjustTrust(state, -2);
      logTimeline(state, "Connexion Keltis Médical coupée — confinement immédiat.");
      return "Connexion Keltis Médical coupée. Rapide et sûr pour l'instant — mais toute trace exploitable sur l'origine exacte de la connexion est perdue.";
    }
    adjustRisk(state, 3);
    adjustTrust(state, 2);
    logTimeline(state, "Connexion Keltis Médical laissée active, sous surveillance.");
    return "Connexion laissée active sous surveillance. Plus risqué dans l'immédiat — mais Moss pourra tracer précisément d'où vient la session suivante.";
  }

  function applyTransmit(state) {
    if (!state.connectedPcanet) return null;
    if (state.transmitted) return null;
    state.transmitted = true;
    var ev = evidenceScore(state);
    if (ev >= 60) adjustTrust(state, 5);
    else if (ev < 30) adjustTrust(state, -5);
    logTimeline(state, "Accès et conclusions transmis au Dr Assaf (preuves : " + ev + "/100).");
    return "Le Dr Assaf confirme la réception et valide un dosage manuel sécurisé.";
  }

  // ---------------------------------------------------------------
  // Objectifs / dénouement / bilan
  // ---------------------------------------------------------------

  function objectiveState(state, id) {
    switch (id) {
      case "obj1": return state.subnetScanned;
      case "obj2": return state.threadVerdict.thread1 === "confirmee";
      case "obj3": return state.threadVerdict.thread2 === "confirmee";
      case "obj4": return state.threadVerdict.thread3 === "ecartee";
      case "obj5": return state.connectedPcanet;
      case "obj6": return state.decision !== null && state.transmitted;
      default: return false;
    }
  }
  function allObjectives(state) {
    return ["obj1", "obj2", "obj3", "obj4", "obj5", "obj6"].map(function (id) {
      return { id: id, label: OBJECTIVE_LABELS[id], done: objectiveState(state, id) };
    });
  }

  function missionComplete(state) {
    return state.connectedPcanet && state.decision !== null && state.transmitted;
  }

  /**
   * Classe le dénouement à partir des quatre dimensions de l'état.
   * Retourne null tant que missionComplete() est faux — condition de
   * victoire/échec vérifiable à tout moment de la partie.
   */
  function computeEnding(state) {
    if (!missionComplete(state)) return null;
    var ev = evidenceScore(state);
    var kind;
    if (state.risk >= 70 || state.trust <= 25) kind = "compromise";
    else if (state.trust >= 75 && ev >= 70 && state.risk <= 30 && !state.failsafeTriggered && !state.authExceeded) kind = "exemplaire";
    else if (ev < 35) kind = "precipitee";
    else if (state.failsafeTriggered || state.timeBudget <= 4) kind = "tendue";
    else kind = "efficace";
    var t = ENDING_TEXT[kind];
    return {
      kind: kind, title: t.title, text: t.text,
      timeRemaining: state.timeBudget, decision: state.decision,
      risk: state.risk, evidence: ev, trust: state.trust
    };
  }

  function computeRecommendations(state) {
    var rec = [];
    if (state.threadVerdict.thread1 === "confirmee") rec.push("Changer immédiatement les identifiants de maintenance par défaut sur PCA-Net et désactiver le compte générique \"tech\".");
    if (state.threadVerdict.thread2 === "confirmee") rec.push("Isoler PCA-Net et le BMS sur deux VLAN distincts, conformément au plan de déploiement initial du prestataire.");
    if (state.threadVerdict.thread3 === "erreur") rec.push("Revérifier les journaux du poste infirmier avant toute communication officielle : aucune preuve technique ne soutient un compromis de ce poste.");
    if (state.authExceeded) rec.push("Documenter et faire valider a posteriori l'accès pris sur le BMS, hors périmètre initialement autorisé pour cette mission.");
    if (state.decision === "cut") rec.push("La coupure immédiate a limité le risque mais a réduit les traces exploitables ; prévoir un protocole de capture de preuves avant coupure pour la prochaine intervention.");
    if (state.decision === "monitor") rec.push("Formaliser la procédure de surveillance engagée avant la prochaine intervention similaire, et fixer un délai de coupure si aucune origine n'est identifiée.");
    if (evidenceScore(state) < 40) rec.push("Documenter plus rigoureusement les découvertes avant toute transmission future : le dossier actuel reste insuffisant pour un rapport d'incident formel.");
    if (rec.length === 0) rec.push("Aucune recommandation supplémentaire : la mission s'est arrêtée avant d'établir de conclusion exploitable.");
    return rec;
  }

  /**
   * Bilan de mission complet, utilisé par l'écran de résolution et
   * directement testable : chronologie, preuves, hypothèses non
   * vérifiées ou erronées, recommandations.
   */
  function computeDebrief(state) {
    var threads = allThreads(state);
    return {
      ending: computeEnding(state),
      chronology: state.timeline.slice(),
      confirmedFindings: threads.filter(function (t) { return t.state === THREAD_CORRECT_VERDICT[t.id] && (t.state === "confirmee" || t.state === "ecartee"); }),
      unverified: threads.filter(function (t) { return t.state === "pending" || t.state === "en-cours"; }),
      wrongConclusions: threads.filter(function (t) { return t.state === "premature" || t.state === "erreur"; }),
      authorizationExceeded: state.authExceeded,
      decision: state.decision,
      metrics: { risk: state.risk, evidence: evidenceScore(state), trust: state.trust, timeRemaining: state.timeBudget },
      recommendations: computeRecommendations(state)
    };
  }

  return {
    TIME_BUDGET_START: TIME_BUDGET_START,
    THREAD_LABELS: THREAD_LABELS,
    OBJECTIVE_LABELS: OBJECTIVE_LABELS,
    createState: createState,
    applyCommand: applyCommand,
    applyDecision: applyDecision,
    applyTransmit: applyTransmit,
    threadState: threadState,
    allThreads: allThreads,
    evidenceScore: evidenceScore,
    objectiveState: objectiveState,
    allObjectives: allObjectives,
    missionComplete: missionComplete,
    computeEnding: computeEnding,
    computeDebrief: computeDebrief
  };
});
