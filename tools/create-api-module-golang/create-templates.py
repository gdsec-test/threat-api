#!/usr/bin/env python

import os
from jinja2 import Environment, FileSystemLoader
from pathlib import Path

PATH = os.path.dirname(os.path.abspath(__file__))
ROOT_THREAT_API = str(Path(PATH).parents[1])
PATH_API = os.path.join(ROOT_THREAT_API, "apis")

TEMPLATE_ENVIRONMENT = Environment(
    autoescape=True,
    loader=FileSystemLoader(os.path.join(PATH, "templates")),
    trim_blocks=False,
)

new_module_path = ""
module_name = ""


def render_template(template_filename, context):
    return TEMPLATE_ENVIRONMENT.get_template(template_filename).render(context)


def create_file_content(new_file_path, new_file_name, template_name, context):
    file_name = os.path.join(new_file_path, new_file_name)
    with open(file_name, "w") as f:
        file_content = render_template(template_name, context)
        f.write(file_content)


if __name__ == "__main__":
    # Create a directory of module name in /threat-api/apis
    print(
        "The current version creates a library structure. Delete the directory if library already exists\n"
    )
    print(
        "All names are mostly populated by the input. Names of functions can be changed as needed \n"
    )
    new_module_name = input("Enter new module name for directory: ").lower()

    new_module_path = os.path.join(PATH_API, new_module_name)
    os.mkdir(new_module_path, 0o755)  # Creating a directory with drwxr-xr-x perms

    # Context contains the variable values to fill in the template, for now it's just module name
    context = {"module": new_module_name}

    create_file_content(
        new_module_path, ".gitignore", "gitignore_template.txt", context
    )  # gitignore
    create_file_content(
        new_module_path, "build.sh", "build_script.txt", context
    )  # build script
    # Give execute permissions for sceptre to pick it up, tagging with nosec for bandit
    os.chmod(os.path.join(new_module_path, new_module_path, "build.sh"), 0o755)  # nosec
    create_file_content(
        new_module_path, "update-lambda.sh", "update_script.txt", context
    )  # update lambda script
    create_file_content(
        new_module_path, "lambda.json", "lambda_json.txt", context
    )  # lambda json

    # Library and basic file for it
    library_path = os.path.join(new_module_path, new_module_name + "Library")
    os.mkdir(library_path, 0o755)  # Creating a directory with drwxr-xr-x perms
    create_file_content(
        library_path,
        new_module_name + "EnrichData.go",
        "library_enrich_data.txt",
        context,
    )  # entry go

    # GO files
    create_file_content(new_module_path, "entry.go", "entry.txt", context)  # entry go
    create_file_content(new_module_path, "triage.go", "triage.txt", context)  # triage
    create_file_content(
        new_module_path, new_module_name + "IoC.go", "module_logic.txt", context
    )  # exampleIoC.go
    create_file_content(
        new_module_path,
        new_module_name + "IoC_test.go",
        "module_logic_test.txt",
        context,
    )  # test file
