$(document).ready(function() {
  var running = false;

  function escapeHtml(value) {
    return String(value).replace(/[&<>"'`=\/]/g, function(character) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
        "/": "&#x2F;",
        "`": "&#x60;",
        "=": "&#x3D;"
      }[character];
    });
  }

  function badgeClass(status) {
    if (status === "ok") return "bg-success";
    if (status === "warning") return "bg-warning text-dark";
    if (status === "running") return "bg-info text-dark";
    return "bg-danger";
  }

  function renderResult(id, data) {
    var status = data.status || "error";
    var steps = data.steps || [];
    var stepHtml = steps.map(function(step) {
      return '<li><span class="badge ' + badgeClass(step.status) + ' me-2">' + escapeHtml(step.status) + '</span>' +
        '<span class="fw-bold">' + escapeHtml(step.label || "step") + '</span>' +
        '<span class="d-block ms-5 text-break">' + escapeHtml(step.message || "") + '</span></li>';
    }).join("");

    $("#" + id).html(
      '<div class="card border">' +
        '<div class="card-header d-flex align-items-center">' +
          '<span class="fw-bold">' + escapeHtml(data.name || id) + '</span>' +
          '<span class="badge ' + badgeClass(status) + ' ms-auto">' + escapeHtml(status) + '</span>' +
        '</div>' +
        '<div class="card-body">' +
          '<p class="mb-2 text-break">' + escapeHtml(data.summary || "") + '</p>' +
          '<ul class="list-unstyled mb-0">' + stepHtml + '</ul>' +
        '</div>' +
      '</div>'
    );
  }

  function renderRunning(id, name) {
    $("#watchdog-empty-state").addClass("d-none");
    if (!$("#" + id).length) {
      $("#watchdog-results").prepend('<div id="' + id + '"></div>');
    }
    renderResult(id, {
      name: name,
      status: "running",
      summary: "Running check...",
      steps: []
    });
  }

  function selectedChecks() {
    return $(".watchdog-check:checked").map(function() {
      return $(this).val();
    }).get();
  }

  function formatTime(value) {
    if (!value) return "-";
    var date = new Date(Date.parse(value));
    if (date instanceof Date && !isNaN(date)) {
      return date.toLocaleString();
    }
    return value;
  }

  function renderEvents(rows) {
    if (!rows.length) {
      $("#watchdog-events").html('<tr><td colspan="4" class="text-muted">No watchdog events found.</td></tr>');
      return;
    }

    $("#watchdog-events").html(rows.map(function(row) {
      return '<tr>' +
        '<td>' + escapeHtml(formatTime(row.time)) + '</td>' +
        '<td>' + escapeHtml(row.service || "") + '</td>' +
        '<td>' + escapeHtml(row.trend || "") + '</td>' +
        '<td class="text-break">' + escapeHtml(row.message || "") + '</td>' +
      '</tr>';
    }).join(""));
  }

  function refreshEvents() {
    $("#watchdog-events").html('<tr><td colspan="4" class="text-muted">Loading events...</td></tr>');
    window.fetch("/api/v1/get/logs/watchdog/100", {
      method: "GET",
      cache: "no-cache"
    }).then(function(response) {
      return response.json();
    }).then(function(data) {
      renderEvents(Array.isArray(data) ? data : []);
    }).catch(function(error) {
      console.log(error);
      $("#watchdog-events").html('<tr><td colspan="4" class="text-warning">Could not load watchdog events.</td></tr>');
    });
  }

  function checkName(check) {
    return $('.watchdog-check[value="' + check + '"]').closest("label").find(".fw-bold").first().text();
  }

  function runCheck(check) {
    var resultId = "watchdog-result-" + check;
    renderRunning(resultId, checkName(check));

    return window.fetch("/inc/ajax/watchdog_check.php?check=" + encodeURIComponent(check), {
      method: "GET",
      cache: "no-cache"
    }).then(function(response) {
      return response.json();
    }).then(function(data) {
      renderResult(resultId, data);
    }).catch(function(error) {
      console.log(error);
      renderResult(resultId, {
        name: checkName(check),
        status: "error",
        summary: "The check request failed.",
        steps: []
      });
    });
  }

  $("#watchdog-run-selected").on("click", function(e) {
    e.preventDefault();
    if (running) return;

    var checks = selectedChecks();
    if (!checks.length) return;

    running = true;
    $("#watchdog-run-state").removeClass("bg-secondary bg-success bg-danger").addClass("bg-info text-dark").text("Running");
    $("#watchdog-run-selected").prop("disabled", true);

    checks.reduce(function(chain, check) {
      return chain.then(function() {
        return runCheck(check);
      });
    }, Promise.resolve()).finally(function() {
      running = false;
      $("#watchdog-run-state").removeClass("bg-info text-dark").addClass("bg-success").text("Complete");
      $("#watchdog-run-selected").prop("disabled", false);
    });
  });

  $("#watchdog-select-all").on("click", function(e) {
    e.preventDefault();
    $(".watchdog-check").prop("checked", true);
  });

  $("#watchdog-clear-results").on("click", function(e) {
    e.preventDefault();
    $("#watchdog-results").html('<div class="text-muted" id="watchdog-empty-state">No checks have been run yet.</div>');
    $("#watchdog-run-state").removeClass("bg-success bg-danger bg-info text-dark").addClass("bg-secondary").text("Idle");
  });

  $("#watchdog-refresh-events").on("click", function(e) {
    e.preventDefault();
    refreshEvents();
  });

  refreshEvents();
});
