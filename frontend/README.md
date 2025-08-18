# Vulnera Frontend - Fully Responsive Drag & Drop Interface

A modern, **fully responsive** drag-and-drop interface for the Vulnera vulnerability analysis API, built with **TailwindCSS** and **DaisyUI**.

## ✨ Features

### 📱 **Fully Responsive Design**
- **Mobile-First Approach** with optimized layouts for all screen sizes
- **Custom Breakpoints**:
  - `xs` (475px+) - Extra small screens
  - `sm` (640px+) - Small screens
  - `md` (768px+) - Medium screens
  - `lg` (1024px+) - Large screens
  - `xl` (1280px+) - Extra large screens
- **Adaptive Content**: Text, buttons, and layouts adjust automatically
- **Touch-Friendly**: Larger touch targets and optimized interactions on mobile

### 🎨 **Design**
- **Clean, modern interface** with professional styling
- **Light/Dark mode toggle** using DaisyUI themes
- **Responsive design** that works perfectly on desktop, tablet, and mobile
- **Smooth animations** with reduced motion support for accessibility
- **Accessible components** with proper ARIA labels and focus states

### 📁 Drag & Drop
- **Intuitive drag and drop zone** for dependency files
- **File validation** with real-time feedback
- **Visual feedback** during drag operations
- **Click to browse** alternative for file selection
- **File type detection** and ecosystem identification

### 🌍 Multi-Language Support
- **8 Programming Language Ecosystems** supported:
  - 🐍 **Python** - PyPI (requirements.txt, Pipfile, pyproject.toml)
  - 📦 **Node.js** - npm (package.json, package-lock.json, yarn.lock)
  - ☕ **Java** - Maven (pom.xml, build.gradle, build.gradle.kts)
  - 🦀 **Rust** - Cargo (Cargo.toml, Cargo.lock)
  - 🐹 **Go** - (go.mod, go.sum)
  - 🐘 **PHP** - Composer (composer.json, composer.lock)
  - 💎 **Ruby** - RubyGems (Gemfile, Gemfile.lock)
  - 🔷 **.NET** - NuGet (*.csproj, packages.config, Directory.Packages.props)

### 🔧 Functionality
- **File test button** with sample package.json
- **Real-time analysis simulation** with loading states
- **Results modal** with vulnerability statistics
- **Download report** functionality
- **Theme persistence** using localStorage

## 🚀 Quick Start

### Environment Configuration

1. Copy the environment template:
```bash
cp .env.example .env
```

2. Edit `.env` and set your API server URL:
```bash
VITE_API_BASE_URL=http://localhost:3000
```

### Available Environment Variables

- `VITE_API_BASE_URL`: The base URL for the Vulnera API server
  - Development: `http://localhost:3000`
  - Production: `https://api.vulnera.dev`
  - Custom server: `http://your-server.com:3000`

### Security Notes

- ⚠️ Never commit `.env` files with production credentials
- 🔒 Use environment-specific configurations for different deployments
- 🛡️ The app falls back to `http://localhost:3000` if no environment variable is set

### Development

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies (if not already done)
npm install

# Start development server
npm run dev

# Open browser to http://localhost:5173 (or the port shown in terminal)
```

## 📱 Responsive Breakpoints

- **Mobile**: `< 768px` - Stacked layout, touch-friendly controls
- **Tablet**: `768px - 1024px` - 2-column grid for language cards
- **Desktop**: `> 1024px` - Full 4-column grid layout

## 🎯 Usage Instructions

1. **Upload a dependency file**:
   - Drag and drop any supported dependency file onto the drop zone
   - Or click the drop zone to browse and select a file
   - Or click "Try Sample File" to load a test package.json

2. **File validation**:
   - Green alert = Supported file format
   - Yellow alert = Unsupported or unknown format
   - Analysis button only enables for supported files

3. **Theme switching**:
   - Click the sun/moon icon in the top-right to toggle themes
   - Theme preference is saved and restored on next visit

4. **Run analysis**:
   - Click "Analyze Vulnerabilities" button (enabled only for supported files)
   - View loading modal during analysis simulation
   - See results in the detailed results modal

## 🏗️ Architecture

### File Structure
```
frontend/
├── index.html          # Main HTML template with DaisyUI theme support
├── package.json        # Dependencies (Vite, TailwindCSS, DaisyUI)
├── vite.config.ts      # Vite configuration with TailwindCSS plugin
└── src/
    ├── main.js         # Main application logic and DOM manipulation
    └── style.css       # Custom styles and TailwindCSS imports
```

### Key Dependencies
- **Vite** `^7.1.2` - Build tool and dev server
- **TailwindCSS** `^4.1.12` - Utility-first CSS framework
- **DaisyUI** `^5.0.50` - Component library for TailwindCSS
- **Font Awesome** `6.0.0` - Icon library (CDN)

### JavaScript Modules
- `initThemeToggle()` - Handles light/dark mode switching
- `initDragAndDrop()` - Manages file drop zone interactions
- `initSampleFile()` - Provides sample file testing functionality

## 🎨 Theme Customization

The interface uses DaisyUI's built-in theming system:

- **Light theme**: Clean whites and subtle grays
- **Dark theme**: Deep backgrounds with high contrast text
- **Primary colors**: Professional blue accents throughout
- **Semantic colors**: Green (success), Yellow (warning), Red (error)

## 🔗 API Integration Ready

The interface is designed to integrate with the Vulnera Rust API:

- Form data ready for POST to `/api/v1/analyze`
- File content extraction for API payload
- Response handling for vulnerability results
- Error state management for API failures

## 📊 Supported File Formats

| Language | Ecosystem | File Formats |
|----------|-----------|-------------|
| Python | PyPI | `requirements.txt`, `Pipfile`, `pyproject.toml` |
| Node.js | npm | `package.json`, `package-lock.json`, `yarn.lock` |
| Java | Maven | `pom.xml`, `build.gradle`, `build.gradle.kts` |
| Rust | Cargo | `Cargo.toml`, `Cargo.lock` |
| Go | Go Modules | `go.mod`, `go.sum` |
| PHP | Composer | `composer.json`, `composer.lock` |
| Ruby | RubyGems | `Gemfile`, `Gemfile.lock` |
| .NET | NuGet | `*.csproj`, `packages.config`, `Directory.Packages.props` |

## 🌟 Footer Information

The footer clearly displays:
- Links to documentation, API examples, and health checks
- Social media icons for project promotion
- Copyright notice with tech stack acknowledgment
- **Compatibility statement** listing all supported ecosystems with their logos

---

**Built with ❤️ and modern web technologies for the Vulnera ecosystem**
