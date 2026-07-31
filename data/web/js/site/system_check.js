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
          (data.guidance ? '<div class="alert alert-info py-2">' + escapeHtml(data.guidance) + '</div>' : '') +
          '<ul class="list-unstyled mb-0">' + stepHtml + '</ul>' +
        '</div>' +
      '</div>'
    );
  }

  function renderRunning(id, name) {
    $("#system-check-empty-state").addClass("d-none");
    if (!$("#" + id).length) {
      $("#system-check-results").prepend('<div id="' + id + '"></div>');
    }
    renderResult(id, {
      name: name,
      status: "running",
      summary: "Running check...",
      steps: []
    });
  }

  function selectedChecks() {
    return $(".system-check:checked").map(function() {
      return $(this).val();
    }).get();
  }

  function checkName(check) {
    return $('.system-check[value="' + check + '"]').closest("label").find(".fw-bold").first().text();
  }

  function runCheck(check) {
    var resultId = "system-check-result-" + check;
    renderRunning(resultId, checkName(check));

    return window.fetch("/inc/ajax/system_check.php?check=" + encodeURIComponent(check), {
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

  $("#system-check-run-selected").on("click", function(e) {
    e.preventDefault();
    if (running) return;

    var checks = selectedChecks();
    if (!checks.length) return;

    running = true;
    $("#system-check-run-state").removeClass("bg-secondary bg-success bg-danger").addClass("bg-info text-dark").text("Running");
    $("#system-check-run-selected").prop("disabled", true);

    checks.reduce(function(chain, check) {
      return chain.then(function() {
        return runCheck(check);
      });
    }, Promise.resolve()).finally(function() {
      running = false;
      $("#system-check-run-state").removeClass("bg-info text-dark").addClass("bg-success").text("Complete");
      $("#system-check-run-selected").prop("disabled", false);
    });
  });

  $("#system-check-select-all").on("click", function(e) {
    e.preventDefault();
    $(".system-check").prop("checked", true);
  });

  $("#system-check-clear-results").on("click", function(e) {
    e.preventDefault();
    $("#system-check-results").html('<div class="text-muted" id="system-check-empty-state">No checks have been run yet.</div>');
    $("#system-check-run-state").removeClass("bg-success bg-danger bg-info text-dark").addClass("bg-secondary").text("Idle");
  });

});
