/**
 * main.js - Client-Side Enhancements for Fake Form Detector
 * Event: BUILD SECURE 2026
 */

document.addEventListener("DOMContentLoaded", () => {
  // 1. Scan Form Submission Loading State
  const scanForm = document.getElementById("scan-form");
  const analyzeBtn = document.getElementById("analyze-btn");
  const urlInput = document.getElementById("url-input");

  if (scanForm && analyzeBtn) {
    scanForm.addEventListener("submit", (e) => {
      const urlVal = urlInput.value.trim();
      if (!urlVal) {
        e.preventDefault();
        urlInput.focus();
        return;
      }

      // Show safe loading state
      analyzeBtn.disabled = true;
      analyzeBtn.innerHTML = `
        <span class="spinner" style="display:inline-block; width:16px; height:16px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation: spin 0.8s linear infinite; vertical-align:middle; margin-right:8px;"></span>
        AUDITING TARGET...
      `;
    });
  }

  // 2. Report Findings Filtering (All, High Risk, Warning, Pass, Unverified)
  const filterBtns = document.querySelectorAll(".filter-btn");
  const findingCards = document.querySelectorAll(".finding-card");

  filterBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      filterBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");

      const filter = btn.getAttribute("data-filter");

      findingCards.forEach((card) => {
        if (filter === "all") {
          card.style.display = "block";
        } else {
          if (card.classList.contains(`severity-${filter}`)) {
            card.style.display = "block";
          } else {
            card.style.display = "none";
          }
        }
      });
    });
  });

  // 3. Print Security Report
  const printBtn = document.getElementById("btn-print-report");
  if (printBtn) {
    printBtn.addEventListener("click", (e) => {
      e.preventDefault();
      window.print();
    });
  }
});

// Inline keyframe helper for the scanning spinner
const style = document.createElement("style");
style.textContent = `
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
`;
document.head.appendChild(style);
