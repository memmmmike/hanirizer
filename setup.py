"""Setup configuration for hanirizer."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read version from package
with open('src/__init__.py') as f:
    for line in f:
        if line.startswith('__version__'):
            __version__ = line.split('=')[1].strip().strip('"').strip("'")

setup(
    name="hanirizer",
    version=__version__,
    author="Network Automation Community",
    author_email="support@example.com",
    description="A robust tool for sanitizing sensitive information in network device configuration files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/memmmmike/hanirizer",
    project_urls={
        "Bug Tracker": "https://github.com/memmmmike/hanirizer/issues",
        "Documentation": "https://github.com/memmmmike/hanirizer/blob/main/README.md",
        "Source Code": "https://github.com/memmmmike/hanirizer",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "pyyaml>=6.0",
        "pyminizip>=0.2.6",  # For password-protected ZIP creation
        "requests>=2.28.0",  # For version checking
        "packaging>=21.0",  # For version comparison
    ],
    # Note: 7z and unrar are system dependencies (see README.md)
    # Linux: sudo apt-get install p7zip-full unrar
    # macOS: brew install p7zip unrar
    # Windows: choco install 7zip unrar
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "isort>=5.12.0",
            "safety>=2.3.0",
            "bandit>=1.7.0",
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "netsan=src.cli:main",
            "network-sanitizer=src.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "src": ["*.json", "*.yaml", "*.yml"],
    },
    zip_safe=False,
    keywords=[
        "network",
        "configuration",
        "sanitization",
        "security",
        "cisco",
        "juniper",
        "arista",
        "paloalto",
        "automation",
        "devops",
        "netops",
    ],
)