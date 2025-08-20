import "./style.css";
import { generateHTMLReport } from "./html-report-generator.js";

// Configuration from environment variables
const CONFIG = {
  API_BASE_URL: 
    (import.meta.env && import.meta.env.VITE_API_BASE_URL) ||
    (typeof window !== "undefined" && window.VULNERA_API_BASE_URL) ||
    "http://localhost:3000", // Fallback to local development server
  
  API_VERSION: 
    (import.meta.env && import.meta.env.VITE_API_VERSION) || 
    "v1",
  
  APP_NAME: 
    (import.meta.env && import.meta.env.VITE_APP_NAME) || 
    "Vulnera",
    
  APP_VERSION: 
    (import.meta.env && import.meta.env.VITE_APP_VERSION) || 
    "1.0.0"
};

// Build complete API URL
const API_BASE_URL = CONFIG.API_BASE_URL;
const API_ENDPOINT = `${API_BASE_URL}/api/${CONFIG.API_VERSION}`;

// Log configuration for debugging (only in development)
if (import.meta.env.DEV) {
  console.log("🔧 App Configuration:", {
    API_BASE_URL,
    API_ENDPOINT,
    APP_NAME: CONFIG.APP_NAME,
    APP_VERSION: CONFIG.APP_VERSION,
    MODE: import.meta.env.MODE
  });
}

// Theme switching functionality
function initThemeToggle() {
  const themeToggle = document.getElementById("theme-toggle");
  const htmlElement = document.documentElement;

  themeToggle.addEventListener("change", function () {
    if (this.checked) {
      htmlElement.setAttribute("data-theme", "dark");
      localStorage.setItem("theme", "dark");
    } else {
      htmlElement.setAttribute("data-theme", "light");
      localStorage.setItem("theme", "light");
    }
  });

  // Load saved theme
  const savedTheme = localStorage.getItem("theme") || "light";
  htmlElement.setAttribute("data-theme", savedTheme);
  themeToggle.checked = savedTheme === "dark";
}

// Drag and drop functionality
function initDragAndDrop() {
  const dropZone = document.getElementById("drop-zone");
  const fileInput = document.getElementById("file-input");
  const fileInfo = document.getElementById("file-info");
  const analyzeBtn = document.getElementById("analyze-btn");

  // Handle drag events
  ["dragenter", "dragover", "dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, preventDefaults, false);
    document.body.addEventListener(eventName, preventDefaults, false);
  });

  ["dragenter", "dragover"].forEach((eventName) => {
    dropZone.addEventListener(eventName, highlight, false);
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, unhighlight, false);
  });

  dropZone.addEventListener("drop", handleDrop, false);
  dropZone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", handleFileSelect);
  analyzeBtn.addEventListener("click", handleAnalyze);

  function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  function highlight() {
    dropZone.classList.add("border-primary", "bg-primary/5");
  }

  function unhighlight() {
    dropZone.classList.remove("border-primary", "bg-primary/5");
  }

  function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    handleFiles(files);
  }

  function handleFileSelect(e) {
    const files = e.target.files;
    handleFiles(files);
  }

  function handleFiles(files) {
    if (files.length > 0) {
      const file = files[0];
      displayFileInfo(file);
    }
  }

  function displayFileInfo(file) {
    const supportedFiles = {
      "package.json": "Node.js",
      "package-lock.json": "Node.js",
      "yarn.lock": "Node.js",
      "requirements.txt": "Python",
      Pipfile: "Python",
      "pyproject.toml": "Python",
      "pom.xml": "Java",
      "build.gradle": "Java",
      "build.gradle.kts": "Java",
      "Cargo.toml": "Rust",
      "Cargo.lock": "Rust",
      "go.mod": "Go",
      "go.sum": "Go",
      "composer.json": "PHP",
      "composer.lock": "PHP",
      Gemfile: "Ruby",
      "Gemfile.lock": "Ruby",
      "packages.config": ".NET",
      "*.csproj": ".NET",
      "Directory.Packages.props": ".NET",
    };

    const ecosystem = supportedFiles[file.name] || "Unknown";
    const isSupported = ecosystem !== "Unknown";

    fileInfo.innerHTML = `
      <div class="alert ${
        isSupported ? "alert-success" : "alert-warning"
      } mb-4">
        <i class="fas ${
          isSupported ? "fa-check-circle" : "fa-exclamation-triangle"
        }"></i>
        <div class="flex-1 min-w-0">
          <div class="font-semibold text-sm sm:text-base truncate">${
            file.name
          }</div>
          <div class="text-xs sm:text-sm opacity-70">
            <span class="font-medium">${ecosystem}</span>
            <span class="hidden xs:inline"> - ${(file.size / 1024).toFixed(
              2
            )} KB</span>
          </div>
        </div>
      </div>
    `;

    analyzeBtn.disabled = !isSupported;
    analyzeBtn.classList.toggle("btn-disabled", !isSupported);
  }

  async function handleAnalyze() {
    const fileInput = document.getElementById("file-input");
    const file = fileInput.files && fileInput.files[0];
    if (!file) {
      try {
        notyf?.open({
          type: "warning",
          message: "Please select a dependency file first.",
        });
      } catch (_) {}
      return;
    }

    const ecosystem = detectEcosystemForApi(file.name);
    if (!ecosystem) {
      try {
        notyf?.open({
          type: "warning",
          message: "This ecosystem isn't supported by the API yet.",
        });
      } catch (_) {}
      return;
    }

    const loadingModal = document.getElementById("loading-modal");
    loadingModal.checked = true;

    try {
      const file_content = await file.text();
      console.log("🔍 API Request to:", `${API_ENDPOINT}/analyze`);
      console.log("📤 Request data:", { ecosystem, filename: file.name });

      const res = await fetch(`${API_ENDPOINT}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ ecosystem, file_content, filename: file.name }),
      });

      console.log("📥 Response status:", res.status, res.statusText);
      const payload = await res.json().catch(() => ({}));
      console.log("📊 Response payload:", payload);

      loadingModal.checked = false;

      if (!res.ok) {
        const message =
          payload?.message ||
          payload?.error ||
          `Request failed (${res.status})`;
        showError(message);
        return;
      }

      // Store analysis data for download
      lastAnalysisData = payload;
      lastAnalysisFileName = file.name;

      renderAnalysisResult(payload);
    } catch (err) {
      loadingModal.checked = false;
      showError("Network error while contacting the API.");
      console.error(err);
    }
  }

  // Map filename to API ecosystem values the backend accepts
  function detectEcosystemForApi(filename) {
    const name = (filename || "").toLowerCase();
    if (
      name === "package.json" ||
      name === "package-lock.json" ||
      name === "yarn.lock"
    )
      return "npm";
    if (
      name === "requirements.txt" ||
      name === "pipfile" ||
      name === "pyproject.toml"
    )
      return "python"; // accepted by API
    if (
      name === "pom.xml" ||
      name.endsWith("build.gradle") ||
      name.endsWith("build.gradle.kts")
    )
      return "maven";
    if (name === "cargo.toml" || name === "cargo.lock") return "cargo";
    if (name === "go.mod" || name === "go.sum") return "go";
    if (name === "composer.json" || name === "composer.lock") return "composer"; // accepted by API
    // Ruby/.NET not yet supported by backend
    return null;
  }

  function showError(message) {
    try {
      notyf?.open({ type: "warning", message });
    } catch (_) {
      alert(message);
    }
  }

  function renderAnalysisResult(data) {
    const resultModal = document.getElementById("result-modal");
    resultModal.checked = true;

    const meta = data?.metadata || {};
    const vulns = Array.isArray(data?.vulnerabilities)
      ? data.vulnerabilities
      : [];

    const sev = meta.severity_breakdown || {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    const vulnItems = vulns
      .slice(0, 50)
      .map(
        (v) => `
        <div class="collapse collapse-arrow bg-base-200">
          <input type="checkbox" />
          <div class="collapse-title text-sm sm:text-base font-medium flex items-center gap-2">
            <span class="badge ${badgeFromSeverity(v.severity)}">${
          v.severity
        }</span>
            <span class="truncate">${escapeHtml(v.id)} — ${escapeHtml(
          v.summary
        )}</span>
          </div>
          <div class="collapse-content text-sm">
            <p class="mb-2 opacity-80">${escapeHtml(v.description || "")}</p>
            ${
              Array.isArray(v.affected_packages) && v.affected_packages.length
                ? `
              <div class="overflow-x-auto">
                <table class="table table-zebra table-xs sm:table-sm">
                  <thead>
                    <tr><th>Package</th><th>Version</th><th>Ecosystem</th></tr>
                  </thead>
                  <tbody>
                    ${v.affected_packages
                      .map(
                        (p) =>
                          `<tr><td>${escapeHtml(p.name)}</td><td>${escapeHtml(
                            p.version
                          )}</td><td>${escapeHtml(p.ecosystem)}</td></tr>`
                      )
                      .join("")}
                  </tbody>
                </table>
              </div>`
                : ""
            }
            ${
              Array.isArray(v.references) && v.references.length
                ? `
              <div class="mt-2 flex flex-wrap gap-2">
                ${v.references
                  .map(
                    (r) =>
                      `<a class="link link-primary text-xs" href="${encodeURI(
                        r
                      )}" target="_blank" rel="noreferrer">${escapeHtml(r)}</a>`
                  )
                  .join("")}
              </div>`
                : ""
            }
          </div>
        </div>`
      )
      .join("");

    document.getElementById("result-content").innerHTML = `
      <div class="space-y-3 sm:space-y-4">
        <div class="alert alert-info">
          <i class="fas fa-info-circle"></i>
          <span class="text-sm sm:text-base">Analysis completed successfully</span>
        </div>
        <div class="stats stats-vertical sm:stats-horizontal shadow w-full">
          <div class="stat p-3 sm:p-4">
            <div class="stat-title text-xs sm:text-sm">Total Packages</div>
            <div class="stat-value text-2xl sm:text-3xl text-primary">${
              meta.total_packages ?? "-"
            }</div>
          </div>
          <div class="stat p-3 sm:p-4">
            <div class="stat-title text-xs sm:text-sm">Vulnerabilities</div>
            <div class="stat-value text-2xl sm:text-3xl text-error">${
              meta.total_vulnerabilities ?? vulns.length
            }</div>
          </div>
          <div class="stat p-3 sm:p-4">
            <div class="stat-title text-xs sm:text-sm">Severity Breakdown</div>
            <div class="stat-desc text-xs">C:${sev.critical} H:${sev.high} M:${
      sev.medium
    } L:${sev.low}</div>
          </div>
        </div>

        ${
          vulnItems
            ? `<div class="mt-4 space-y-2">${vulnItems}</div>`
            : `
          <div class="alert alert-success">
            <i class="fas fa-check-circle"></i>
            <span>No known vulnerabilities found.</span>
          </div>`
        }
      </div>
    `;

    // Add download functionality
    setupDownloadButton(data);
  }

  function setupDownloadButton(data) {
    const downloadBtn = document.getElementById("download-report-btn");
    if (downloadBtn && data) {
      downloadBtn.disabled = false;
      downloadBtn.onclick = async () => {
        try {
          // Generate HTML report
          const fileName = lastAnalysisFileName || "dependency-analysis";
          const htmlContent = generateHTMLReport(data, fileName);

          // Create and download HTML file
          const blob = new Blob([htmlContent], {
            type: "text/html;charset=utf-8",
          });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `vulnera-report-${fileName.replace(/\.[^/.]+$/, "")}-${
            new Date().toISOString().split("T")[0]
          }.html`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);

          // Show success notification
          try {
            notyf?.open({
              type: "success",
              message: "HTML report downloaded successfully!",
            });
          } catch (_) {}
        } catch (error) {
          console.error("Download failed:", error);
          try {
            notyf?.open({
              type: "warning",
              message: "Download failed. Please try again.",
            });
          } catch (_) {}
        }
      };
    }
  }

  function badgeFromSeverity(sev) {
    const s = String(sev || "").toLowerCase();
    if (s === "critical") return "badge-error";
    if (s === "high") return "badge-warning";
    if (s === "medium") return "badge-accent";
    return "badge-ghost";
  }

  function escapeHtml(str) {
    return String(str || "").replace(
      /[&<>"]+/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
        }[c])
    );
  }
}

// Initialize the app
document.addEventListener("DOMContentLoaded", function () {
  document.querySelector("#app").innerHTML = `
    <!-- Navigation -->
    <div class="navbar bg-base-100 shadow-lg px-2 sm:px-4">
      <div class="flex-1">
        <a class="btn btn-ghost text-2xl sm:text-3xl">
          <img src="/images/logo.png" alt="Vulnera Logo" class="h-10 sm:h-20 w-auto mr-2">
        </a>
      </div>
      <div class="flex-none">
        <label class="swap swap-rotate">
          <input type="checkbox" id="theme-toggle" />
          <i class="swap-off fas fa-sun text-yellow-500 text-lg sm:text-xl"></i>
          <i class="swap-on fas fa-moon text-blue-500 text-lg sm:text-xl"></i>
        </label>
      </div>
    </div>

    <!-- Main Content -->
    <div class="min-h-screen bg-base-200 p-2 sm:p-4">
      <div class="max-w-7xl mx-auto">
        <!-- Hero Section -->
        <div class="text-center mb-6 sm:mb-8">
          <div class="flex justify-center mb-2">
            <img src="/images/logo.png" alt="Vulnera Logo" class="h-24 sm:h-38 md:h-47 lg:h-58 xl:h-70 w-auto">
          </div>
      
          </h1>
          <p class="text-base sm:text-lg md:text-xl opacity-70 mb-3 sm:mb-4 px-4">
            Comprehensive vulnerability analysis for your dependencies
          </p>
          <div class="flex flex-wrap justify-center gap-2 sm:gap-4 mb-6 sm:mb-8 px-4">
            <div class="badge badge-primary badge-sm sm:badge-md lg:badge-lg">Multi-Language Support</div>
            <div class="badge badge-secondary badge-sm sm:badge-md lg:badge-lg">Real-time Analysis</div>
            <div class="badge badge-accent badge-sm sm:badge-md lg:badge-lg">Open Source APIs</div>
          </div>
          <div class="flex flex-col sm:flex-row justify-center gap-3 sm:gap-4 px-4">
            <a href="/docs" class="btn btn-outline btn-primary btn-sm sm:btn-md">
              <i class="fas fa-book"></i>
              <span class="hidden xs:inline">Documentation</span>
              <span class="xs:hidden">Docs</span>
            </a>
            <a href="/docs/api-examples" class="btn btn-outline btn-secondary btn-sm sm:btn-md">
              <i class="fas fa-code"></i>
              <span class="hidden xs:inline">API Examples</span>
              <span class="xs:hidden">API</span>
            </a>
            <button id="sample-btn" class="btn btn-outline btn-accent btn-sm sm:btn-md">
              <i class="fas fa-download"></i>
              <span class="hidden xs:inline">Try Sample File</span>
              <span class="xs:hidden">Sample</span>
            </button>
            <button id="github-scan-btn" class="btn btn-outline btn-warning btn-sm sm:btn-md">
              <i class="fab fa-github"></i>
              <span class="hidden xs:inline">Scan GitHub Repo</span>
              <span class="xs:hidden">GitHub</span>
            </button>
          </div>
        </div>

        <!-- Drag & Drop Zone -->
        <div class="card bg-base-100 shadow-xl mb-6 sm:mb-8">
          <div class="card-body p-4 sm:p-6 lg:p-8">
            <h2 class="card-title text-xl sm:text-2xl mb-4 sm:mb-6 justify-center sm:justify-start">
              <i class="fas fa-upload text-primary"></i>
              <span class="hidden xs:inline">Upload Dependency File</span>
              <span class="xs:hidden">Upload File</span>
            </h2>

            <div
              id="drop-zone"
              class="border-2 border-dashed border-base-300 rounded-lg p-6 sm:p-8 lg:p-12 text-center cursor-pointer hover:border-primary transition-all duration-300"
            >
              <div class="space-y-3 sm:space-y-4">
                <i class="fas fa-cloud-upload-alt text-4xl sm:text-5xl lg:text-6xl text-primary opacity-50"></i>
                <div>
                  <p class="text-lg sm:text-xl font-semibold">Drop your dependency file here</p>
                  <p class="opacity-60 text-sm sm:text-base">or click to browse files</p>
                </div>
                <div class="badge badge-outline badge-lg text-xs sm:text-sm px-4 py-5 border-2">
                  <span class="hidden sm:inline">Supported files: package.json, requirements.txt, Cargo.toml, and more</span>
                  <span class="sm:hidden">Supports: package.json, requirements.txt, etc.</span>
                </div>
              </div>
            </div>

            <input type="file" id="file-input" class="hidden" accept=".json,.txt,.toml,.xml,.gradle,.lock,.props">

            <div id="file-info"></div>

            <div class="card-actions justify-center mt-4 sm:mt-6">
              <button id="analyze-btn" class="btn btn-primary btn-sm sm:btn-md lg:btn-lg w-full sm:w-auto" disabled>
                <i class="fas fa-search"></i>
                <span class="hidden xs:inline">Analyze Vulnerabilities</span>
                <span class="xs:hidden">Analyze</span>
              </button>
            </div>
          </div>
        </div>

        <!-- Coming Soon Features -->
        <div class="card bg-gradient-to-r shadow-xl mb-6 sm:mb-8">
          <div class="card-body p-4 sm:p-6 lg:p-8">
            <h2 class="card-title text-xl sm:text-2xl mb-4 sm:mb-6 justify-center text-amber-700 dark:text-warning">
              <i class="fas fa-rocket text-amber-600 dark:text-warning"></i>
              <span class="hidden xs:inline">Coming Soon Features</span>
              <span class="xs:hidden">Coming Soon</span>
            </h2>

            <div class="text-center">
              <div class="mb-4">
                <i class="fab fa-github text-4xl sm:text-5xl text-amber-600 dark:text-warning opacity-80 mb-3"></i>
                <h3 class="text-lg sm:text-xl font-semibold mb-2 text-amber-800 dark:text-amber-200">GitHub Repository Scanning</h3>
                <p class="text-sm sm:text-base opacity-80 mb-4 text-amber-700 dark:text-amber-300">
                  <span class="hidden sm:inline">Automatically scan entire GitHub repositories for vulnerabilities across all dependency files. Support for public and private repos with OAuth integration.</span>
                  <span class="sm:hidden">Scan entire GitHub repos for vulnerabilities automatically.</span>
                </p>
                <button id="github-scan-preview" class="btn btn-warning btn-sm sm:btn-md">
                  <i class="fab fa-github"></i>
                  <span class="hidden xs:inline">Preview GitHub Scanning</span>
                  <span class="xs:hidden">Preview</span>
                </button>
              </div>

              <div class="divider opacity-30">
                <span class="text-xs text-amber-600 dark:text-amber-400 font-medium">ROADMAP</span>
              </div>

              <div class="text-xs sm:text-sm opacity-70 text-amber-700 dark:text-amber-300">
                <p class="mb-2 font-semibold">Planned Features:</p>
                <div class="flex flex-wrap justify-center gap-2 text-xs">
                  <span class="badge bg-amber-200 text-amber-800 border-amber-300 badge-xs sm:badge-sm dark:badge-warning">OAuth Integration</span>
                  <span class="badge bg-amber-200 text-amber-800 border-amber-300 badge-xs sm:badge-sm dark:badge-warning">Bulk Scanning</span>
                  <span class="badge bg-amber-200 text-amber-800 border-amber-300 badge-xs sm:badge-sm dark:badge-warning">CI/CD Integration</span>
                  <span class="badge bg-amber-200 text-amber-800 border-amber-300 badge-xs sm:badge-sm dark:badge-warning">Report Export</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Supported Languages -->
        <div class="card bg-base-100 shadow-xl">
          <div class="card-body p-4 sm:p-6 lg:p-8">
            <h2 class="card-title text-xl sm:text-2xl mb-4 sm:mb-6 justify-center sm:justify-start">
              <i class="fas fa-code text-primary"></i>
              <span class="hidden xs:inline">Supported Languages & Ecosystems</span>
              <span class="xs:hidden">Supported Languages</span>
            </h2>

            <div class="grid grid-cols-1 xs:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-4 gap-3 sm:gap-4 lg:gap-6">
              <!-- Python -->
              <div class="flex flex-col items-center p-3 sm:p-4 rounded-lg bg-base-200 hover:bg-primary hover:text-primary-content transition-all duration-300 hover:scale-105">
                <i class="fab fa-python text-3xl sm:text-4xl text-blue-500 mb-2 sm:mb-3"></i>
                <h3 class="font-semibold text-base sm:text-lg">Python</h3>
                <p class="text-xs sm:text-sm opacity-70 text-center leading-tight">
                  <span class="hidden sm:inline">PyPI, requirements.txt, Pipfile, pyproject.toml</span>
                  <span class="sm:hidden">PyPI, requirements.txt</span>
                </p>
              </div>

              <!-- Node.js -->
              <div class="flex flex-col items-center p-3 sm:p-4 rounded-lg bg-base-200 hover:bg-primary hover:text-primary-content transition-all duration-300 hover:scale-105">
                <i class="fab fa-node-js text-3xl sm:text-4xl text-green-500 mb-2 sm:mb-3"></i>
                <h3 class="font-semibold text-base sm:text-lg">Node.js</h3>
                <p class="text-xs sm:text-sm opacity-70 text-center leading-tight">
                  <span class="hidden sm:inline">npm, package.json, yarn.lock</span>
                  <span class="sm:hidden">npm, package.json</span>
                </p>
              </div>

              <!-- Java -->
              <div class="flex flex-col items-center p-3 sm:p-4 rounded-lg bg-base-200 hover:bg-primary hover:text-primary-content transition-all duration-300 hover:scale-105">
                <i class="fab fa-java text-3xl sm:text-4xl text-red-500 mb-2 sm:mb-3"></i>
                <h3 class="font-semibold text-base sm:text-lg">Java</h3>
                <p class="text-xs sm:text-sm opacity-70 text-center leading-tight">
                  <span class="hidden sm:inline">Maven, pom.xml, build.gradle</span>
                  <span class="sm:hidden">Maven, pom.xml</span>
                </p>
              </div>

              <!-- Rust -->
              <div class="flex flex-col items-center p-3 sm:p-4 rounded-lg bg-base-200 hover:bg-primary hover:text-primary-content transition-all duration-300 hover:scale-105">
                <i class="fab fa-rust text-3xl sm:text-4xl text-orange-600 mb-2 sm:mb-3"></i>
                <h3 class="font-semibold text-base sm:text-lg">Rust</h3>
                <p class="text-xs sm:text-sm opacity-70 text-center leading-tight">
                  <span class="hidden sm:inline">Cargo, Cargo.toml, Cargo.lock</span>
                  <span class="sm:hidden">Cargo, Cargo.toml</span>
                </p>
              </div>

              <!-- Go -->
              <div class="flex flex-col items-center p-3 sm:p-4 rounded-lg bg-base-200 hover:bg-primary hover:text-primary-content transition-all duration-300 hover:scale-105">
                <i class="fab fa-golang text-3xl sm:text-4xl text-cyan-500 mb-2 sm:mb-3"></i>
                <h3 class="font-semibold text-base sm:text-lg">Go</h3>
                <p class="text-xs sm:text-sm opacity-70 text-center leading-tight">go.mod, go.sum</p>
              </div>

              <!-- PHP -->
              <div class="flex flex-col items-center p-3 sm:p-4 rounded-lg bg-base-200 hover:bg-primary hover:text-primary-content transition-all duration-300 hover:scale-105">
                <i class="fab fa-php text-3xl sm:text-4xl text-purple-600 mb-2 sm:mb-3"></i>
                <h3 class="font-semibold text-base sm:text-lg">PHP</h3>
                <p class="text-xs sm:text-sm opacity-70 text-center leading-tight">
                  <span class="hidden sm:inline">Composer, composer.json, composer.lock</span>
                  <span class="sm:hidden">Composer, composer.json</span>
                </p>
              </div>

              <!-- Ruby -->
              <div class="flex flex-col items-center p-3 sm:p-4 rounded-lg bg-base-200 hover:bg-primary hover:text-primary-content transition-all duration-300 hover:scale-105">
                <i class="fas fa-gem text-3xl sm:text-4xl text-red-600 mb-2 sm:mb-3"></i>
                <h3 class="font-semibold text-base sm:text-lg">Ruby</h3>
                <p class="text-xs sm:text-sm opacity-70 text-center leading-tight">
                  <span class="hidden sm:inline">RubyGems, Gemfile, Gemfile.lock</span>
                  <span class="sm:hidden">RubyGems, Gemfile</span>
                </p>
              </div>

              <!-- .NET -->
              <div class="flex flex-col items-center p-3 sm:p-4 rounded-lg bg-base-200 hover:bg-primary hover:text-primary-content transition-all duration-300 hover:scale-105">
                <i class="fab fa-microsoft text-3xl sm:text-4xl text-blue-600 mb-2 sm:mb-3"></i>
                <h3 class="font-semibold text-base sm:text-lg">.NET</h3>
                <p class="text-xs sm:text-sm opacity-70 text-center leading-tight">
                  <span class="hidden sm:inline">NuGet, *.csproj, packages.config</span>
                  <span class="sm:hidden">NuGet, *.csproj</span>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Footer -->
    <footer class="footer footer-center p-6 sm:p-10 bg-base-200 text-base-content">
      <div class="grid grid-flow-col gap-2 sm:gap-4 text-sm sm:text-base">
        <a class="link link-hover" href="/docs">
          <span class="hidden xs:inline">Documentation</span>
          <span class="xs:hidden">Docs</span>
        </a>
        <a class="link link-hover" href="/docs/api-examples">
          <span class="hidden xs:inline">API Examples</span>
          <span class="xs:hidden">API</span>
        </a>
        <a class="link link-hover" href="/health">
          <span class="hidden xs:inline">Health Check</span>
          <span class="xs:hidden">Health</span>
        </a>
      </div>
      <div>
        <div class="grid grid-flow-col gap-3 sm:gap-4">
          <a href="https://github.com" class="text-xl sm:text-2xl hover:text-primary transition-colors">
            <i class="fab fa-github"></i>
          </a>
          <a href="https://twitter.com" class="text-xl sm:text-2xl hover:text-primary transition-colors">
            <i class="fab fa-twitter"></i>
          </a>
          <a href="https://linkedin.com" class="text-xl sm:text-2xl hover:text-primary transition-colors">
            <i class="fab fa-linkedin"></i>
          </a>
        </div>
      </div>
      <div class="text-center">
        <p class="text-sm sm:text-base">© 2025 Vulnera - Built with ID-Brains</p>
        <p class="text-xs sm:text-sm opacity-70 px-4">
          <span class="hidden sm:inline">Compatible with Python, Node.js, Java, Rust, Go, PHP, Ruby & .NET ecosystems</span>
          <span class="sm:hidden">vulnerability toolkit</span>
        </p>
      </div>
    </footer>

    <!-- Loading Modal -->
    <input type="checkbox" id="loading-modal" class="modal-toggle" />
    <div class="modal modal-bottom sm:modal-middle">
      <div class="modal-box w-11/12 max-w-md mx-auto">
        <h3 class="font-bold text-lg sm:text-xl mb-4 text-center">Analyzing Dependencies</h3>
        <div class="flex flex-col items-center space-y-3 sm:space-y-4 py-4">
          <span class="loading loading-spinner loading-lg text-primary"></span>
          <p class="text-sm sm:text-base text-center">Scanning for vulnerabilities...</p>
        </div>
      </div>
    </div>

    <!-- Result Modal -->
    <input type="checkbox" id="result-modal" class="modal-toggle" />
    <div class="modal modal-bottom sm:modal-middle">
      <div class="modal-box w-11/12 max-w-5xl mx-auto">
        <label for="result-modal" class="btn btn-sm btn-circle btn-ghost absolute right-2 top-2">✕</label>
        <h3 class="font-bold text-lg sm:text-xl mb-4">Analysis Results</h3>
        <div id="result-content" class="overflow-x-auto"></div>
        <div class="modal-action flex-col sm:flex-row gap-2 sm:gap-4">
          <label for="result-modal" class="btn btn-outline w-full sm:w-auto order-2 sm:order-1">Close</label>
          <button id="download-report-btn" class="btn btn-primary w-full sm:w-auto order-1 sm:order-2" disabled>
            <i class="fas fa-download"></i>
            <span class="hidden xs:inline ml-2">Download HTML Report</span>
            <span class="xs:hidden ml-2">Download</span>
          </button>
        </div>
      </div>
    </div>
  `;

  initThemeToggle();
  initDragAndDrop();
  initSampleFile();

  // Initialize GitHub scanning (with delay to ensure Notyf is loaded)
  setTimeout(() => {
    if (typeof Notyf !== "undefined") {
      initGitHubScanning();
    }
  }, 100);
});

// Sample file functionality
function initSampleFile() {
  document.getElementById("sample-btn").addEventListener("click", function () {
    // Create a sample file for testing
    const sampleContent = {
      name: "vulnerable-app",
      version: "1.0.0",
      description: "Sample package.json for testing vulnerability analysis",
      dependencies: {
        express: "4.17.1",
        lodash: "4.17.20",
        axios: "0.21.1",
        moment: "2.29.1",
        jquery: "3.5.1",
      },
      devDependencies: {
        jest: "26.6.3",
        eslint: "7.32.0",
      },
    };

    const blob = new Blob([JSON.stringify(sampleContent, null, 2)], {
      type: "application/json",
    });
    const file = new File([blob], "package.json", { type: "application/json" });

    // Simulate file selection
    const fileInput = document.getElementById("file-input");
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(file);
    fileInput.files = dataTransfer.files;

    // Create file info display function locally
    const fileInfo = document.getElementById("file-info");
    const analyzeBtn = document.getElementById("analyze-btn");

    const supportedFiles = {
      "package.json": "Node.js",
      "package-lock.json": "Node.js",
      "yarn.lock": "Node.js",
      "requirements.txt": "Python",
      Pipfile: "Python",
      "pyproject.toml": "Python",
      "pom.xml": "Java",
      "build.gradle": "Java",
      "build.gradle.kts": "Java",
      "Cargo.toml": "Rust",
      "Cargo.lock": "Rust",
      "go.mod": "Go",
      "go.sum": "Go",
      "composer.json": "PHP",
      "composer.lock": "PHP",
      Gemfile: "Ruby",
      "Gemfile.lock": "Ruby",
      "packages.config": ".NET",
      "*.csproj": ".NET",
      "Directory.Packages.props": ".NET",
    };

    const ecosystem = supportedFiles[file.name] || "Unknown";
    const isSupported = ecosystem !== "Unknown";

    fileInfo.innerHTML = `
      <div class="alert ${
        isSupported ? "alert-success" : "alert-warning"
      } mb-4">
        <i class="fas ${
          isSupported ? "fa-check-circle" : "fa-exclamation-triangle"
        }"></i>
        <div class="flex-1 min-w-0">
          <div class="font-semibold text-sm sm:text-base truncate">${
            file.name
          }</div>
          <div class="text-xs sm:text-sm opacity-70">
            <span class="font-medium">${ecosystem}</span>
            <span class="hidden xs:inline"> - ${(file.size / 1024).toFixed(
              2
            )} KB</span>
          </div>
        </div>
      </div>
    `;

    analyzeBtn.disabled = !isSupported;
    analyzeBtn.classList.toggle("btn-disabled", !isSupported);
  });
}

// Initialize Notyf for notifications
let notyf;
let lastAnalysisData = null;
let lastAnalysisFileName = null;

// GitHub repo scanning functionality
function initGitHubScanning() {
  // Initialize Notyf with custom configuration
  notyf = new Notyf({
    duration: 5000,
    position: {
      x: "right",
      y: "top",
    },
    types: [
      {
        type: "info",
        background: "#3B82F6",
        icon: {
          className: "fas fa-info-circle",
          tagName: "i",
          color: "white",
        },
      },
      {
        type: "warning",
        background: "#F59E0B",
        icon: {
          className: "fas fa-exclamation-triangle",
          tagName: "i",
          color: "white",
        },
      },
      {
        type: "success",
        background: "#10B981",
        icon: {
          className: "fas fa-check-circle",
          tagName: "i",
          color: "white",
        },
      },
      {
        type: "github",
        background: "#1F2937",
        icon: {
          className: "fab fa-github",
          tagName: "i",
          color: "white",
        },
      },
    ],
  });

  // GitHub scan button in hero section
  document
    .getElementById("github-scan-btn")
    .addEventListener("click", function () {
      showGitHubComingSoon();
    });

  // GitHub scan preview button in coming soon section
  document
    .getElementById("github-scan-preview")
    .addEventListener("click", function () {
      showGitHubComingSoon();
    });

  function showGitHubComingSoon() {
    // Show coming soon notification
    notyf.open({
      type: "github",
      message:
        "🚀 GitHub Repository Scanning - Coming Soon! Scan entire repos for vulnerabilities across all dependency files.",
    });

    // Show additional info after 2.5 seconds
    setTimeout(() => {
      notyf.open({
        type: "info",
        message:
          "✨ Features: OAuth integration, bulk scanning, automated CI/CD workflows, and comprehensive reporting.",
      });
    }, 2500);

    // Show feature timeline after 5 seconds
    setTimeout(() => {
      notyf.open({
        type: "success",
        message:
          "📅 Expected Release: Q1 2026 | Follow our GitHub for beta access and updates!",
      });
    }, 5000);
  }
}
