# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys

sys.path.insert(0, os.path.abspath(".."))

import sphinx_rtd_theme

# -- Project information -----------------------------------------------------
project = "DataTrails"
copyright = "2023, support@datatrails.ai"
author = "support@datatrails.ai"

version = "0.0.1a"
release = "0.0.1a"


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx_gallery.load_style",
    "sphinx_rtd_theme",
    "sphinxcontrib.spelling",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.autosummary",
    "sphinx.ext.githubpages",
    "sphinx.ext.napoleon",
    "sphinx.ext.todo",
    "sphinx.ext.viewcode",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_site", "Thumbs.db", ".DS_Store", "unittests"]

source_suffix = [".md", ".rst"]
# -- markdown configuration

myst_enable_extensions = [
    "amsmath",
    "attrs_inline",
    "colon_fence",
    "deflist",
    "dollarmath",
    "fieldlist",
    "html_admonition",
    "html_image",
    # "linkify",
    "replacements",
    "smartquotes",
    "strikethrough",
    "substitution",
    "tasklist",
]

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#

# These paths are either relative to html_static_path
# or fully qualified paths (eg. https://...)
# Note this assumes that the contents of docs/datatrails-css/* are copied to _site/css/*
html_css_files = [
    "css/datatrails_theme.css",
]
html_favicon = "_static/favicon.ico"
html_logo = "_static/DataTrails_WhtLogo_RGB.png"
html_show_sourcelink = False
html_show_sphinx = False
# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "analytics_id": "G-7K46H3KK7N",  #  Provided by Google in your dashboard
    "logo_only": True,
}
