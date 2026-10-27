# Contributing to AI Port Scan Risk Intelligence Engine

Thank you for your interest in contributing! Here's how you can help.

## 🤝 Ways to Contribute

- 🐛 **Report Bugs** - Found an issue? Open a GitHub issue
- 💡 **Suggest Features** - Have an idea? Share it in discussions
- 📖 **Improve Documentation** - Help clarify docs and examples
- 🔧 **Fix Code** - Submit pull requests for improvements
- 🧪 **Test & Report** - Verify code and report edge cases

## 📋 Getting Started

### 1. Fork the Repository
```bash
# Click "Fork" on GitHub
git clone https://github.com/your-username/AI_PortScan_Analyzer.git
cd AI_PortScan_Analyzer
```

### 2. Create a Feature Branch
```bash
git checkout -b feature/your-feature-name
```

### 3. Set Up Development Environment
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt requirements_api.txt
pip install pytest black flake8  # Testing/linting
```

### 4. Make Your Changes
```bash
# Make code changes
# Run tests
pytest tests/

# Format code
black scripts/ api.py

# Check style
flake8 scripts/ api.py
```

### 5. Commit & Push
```bash
git add .
git commit -m "Add: Brief description of changes"
git push origin feature/your-feature-name
```

### 6. Create a Pull Request
- Go to GitHub and click "New Pull Request"
- Describe your changes clearly
- Link any related issues

## 📝 Commit Guidelines

```
Format: <Type>: <Brief description>

Types:
- Add: New feature or file
- Fix: Bug fix
- Docs: Documentation updates
- Refactor: Code restructuring (no functional change)
- Test: Adding/updating tests
- Style: Formatting, linting changes

Examples:
- Add: Admin monitoring dashboard endpoint
- Fix: SHAP calculation error in hybrid scoring
- Docs: Update API endpoint examples
```

## 🎯 Code Style

### Python Style
- Follow PEP 8
- Use Black for formatting
- Use type hints where possible
- Add docstrings to functions

```python
def analyze_scan(xml_path: str) -> dict:
    """
    Analyze Nmap XML scan and return structured results.
    
    Args:
        xml_path: Path to Nmap XML file
        
    Returns:
        Dictionary with dashboard, report, and admin views
    """
    pass
```

### FastAPI Endpoints
- Use descriptive names
- Include docstrings with examples
- Validate input with Pydantic
- Return consistent error responses

## 🧪 Testing

### Run Existing Tests
```bash
pytest tests/ -v
```

### Add Tests for New Features
```python
# tests/test_api.py
def test_scan_endpoint():
    response = client.post("/scan", files={"xml_file": ...})
    assert response.status_code == 200
    assert "scan_id" in response.json()
```

## 📚 Areas for Contribution

### High Priority
- [ ] Persistent database for scan storage (instead of in-memory cache)
- [ ] Unit tests for ML prediction logic
- [ ] API authentication improvements
- [ ] Documentation improvements
- [ ] Docker support

### Medium Priority
- [ ] Scan result pagination and filtering
- [ ] Frontend React dashboard
- [ ] Rate limiting and throttling
- [ ] Request logging and audit trail
- [ ] Performance optimizations

### Low Priority
- [ ] GUI for local testing
- [ ] Kubernetes manifests
- [ ] Additional ML models (comparison)
- [ ] Advanced analytics dashboard
- [ ] Mobile app

## 🐛 Reporting Bugs

### Before Creating an Issue
- Check if issue already exists
- Test with latest code from main branch
- Include Python version: `python --version`
- Include relevant versions: `pip list`

### Create a Bug Report
```markdown
**Title:** Brief description

**Describe the bug:**
What happened?

**Steps to reproduce:**
1. ...
2. ...

**Expected behavior:**
What should happen?

**Actual behavior:**
What actually happened?

**Environment:**
- OS: Windows/Linux/Mac
- Python: 3.x
- FastAPI: x.x.x
- XGBoost: x.x.x

**Error output:**
```python
Error message (if any)
```
```

## 💡 Suggesting Enhancements

```markdown
**Title:** Clear feature description

**Problem:**
What problem does this solve?

**Proposed solution:**
How should it work?

**Use case:**
When would this be useful?

**Alternatives considered:**
Other approaches?
```

## 📖 Documentation

### Update Docs When
- Adding new endpoints
- Changing API behavior
- Adding new features
- Fixing unclear explanations

### Documentation Files
- `README.md` - Main overview
- `API_BACKEND_RESTRUCTURING.md` - API detailed guide
- `QUICK_REFERENCE.md` - Quick start
- `IMPLEMENTATION_VERIFICATION.md` - Verification checklist

## ✅ Pull Request Checklist

Before submitting, ensure:

- [ ] Code follows PEP 8 style guide
- [ ] Tests pass: `pytest tests/ -v`
- [ ] Code is formatted: `black .`
- [ ] Linting passes: `flake8 .`
- [ ] Documentation updated
- [ ] Type hints added
- [ ] No secret keys committed
- [ ] Commit messages are clear
- [ ] PR description explains changes

## 🚀 Review Process

1. **CI/CD Checks** - Automated tests must pass
2. **Code Review** - Maintainers review code quality
3. **Feedback** - Address any requested changes
4. **Approval** - Maintainer approves
5. **Merge** - PR merged to main

## 📞 Questions?

- 📖 Read the documentation
- 💬 Check GitHub discussions
- 🐛 Open an issue (if it's a bug)
- 📧 Contact maintainers

## 🎉 Thank You!

Thank you for contributing to the AI Port Scan Risk Intelligence Engine! Your contributions help make cybersecurity more accessible and intelligent.

---

**Happy Coding! 🚀**
