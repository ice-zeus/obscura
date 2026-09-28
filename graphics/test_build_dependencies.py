"""Offline recipe tests. Mocks never fetch, build or load native graphics.

Authoring these tests is separate from running them during platform validation.
Run with: python3 -m unittest discover -s graphics -p test_build_dependencies.py
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("graphics_recipe", Path(__file__).with_name("build_dependencies.py"))
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)


class DependencyRecipeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work, self.output = self.root / "work", self.root / "bundle"

    def test_gn_backends_have_explicit_headless_and_platform_gates(self):
        linux = recipe.gn_arguments("linux")
        self.assertIn("angle_enable_vulkan=true", linux)
        self.assertIn("angle_enable_swiftshader=true", linux)
        for key in ["x11", "wayland", "gbm"]:
            self.assertIn(f"angle_use_{key}=false", linux)
        self.assertIn('angle_vulkan_display_mode="offscreen"', linux)
        mac = recipe.gn_arguments("macos")
        self.assertIn("angle_enable_metal=true", mac)
        self.assertIn("angle_enable_swiftshader=false", mac)
        self.assertIn("angle_enable_vulkan=false", mac)
        with self.assertRaises(ValueError):
            recipe.gn_arguments("unsupported")

    def test_checkout_creates_only_the_requested_pin(self):
        path = self.root / "angle"
        pin = recipe.PINS["angle"]
        with patch.object(recipe, "run") as run:
            recipe.checkout(path, pin, {})
        self.assertTrue(path.is_dir())
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands, [["git", "init", "."],
            ["git", "remote", "add", "origin", pin["repository"]],
            ["git", "fetch", "--depth", "1", "origin", pin["commit"]],
            ["git", "checkout", "--detach", pin["commit"]]])

    def test_checkout_refuses_foreign_remote_or_tracked_modifications(self):
        path = self.root / "angle"; path.mkdir(); pin = recipe.PINS["angle"]
        for replies in [["https://unexpected.example/repo"], [pin["repository"], " M source.cc"]]:
            with self.subTest(replies=replies), patch.object(recipe, "run", side_effect=replies) as run:
                with self.assertRaises(RuntimeError): recipe.checkout(path, pin, {})
                self.assertFalse(any(call.args[0][1] in ["fetch", "checkout"] for call in run.call_args_list))

    def test_checkout_reuses_exact_clean_pin_and_fetches_a_different_clean_pin(self):
        path = self.root / "angle"; path.mkdir(); pin = recipe.PINS["angle"]
        with patch.object(recipe, "run", side_effect=[pin["repository"], "", pin["commit"]]) as run:
            recipe.checkout(path, pin, {})
            self.assertEqual(run.call_count, 3)
        with patch.object(recipe, "run", side_effect=[pin["repository"], "", "older", None, None]) as run:
            recipe.checkout(path, pin, {})
            self.assertEqual(run.call_args_list[-1].args[0], ["git", "checkout", "--detach", pin["commit"]])

    def test_process_errors_propagate_and_capture_is_explicit(self):
        result = subprocess.CompletedProcess(["tool"], 0, " result\n", "")
        with patch.object(recipe.subprocess, "run", return_value=result) as run:
            self.assertEqual(recipe.run([Path("tool")], cwd=self.root, env={}, capture=True), "result")
            self.assertTrue(run.call_args.kwargs["check"])
            self.assertIsNone(recipe.run(["tool"], cwd=self.root, env={}))
        with patch.object(recipe.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["tool"])):
            with self.assertRaises(subprocess.CalledProcessError): recipe.run(["tool"], cwd=self.root, env={})

    def test_artifact_selection_rejects_missing_and_ambiguous_results(self):
        build = self.root / "build"; build.mkdir()
        with self.assertRaises(RuntimeError): recipe.artifact(build, "libEGL.so")
        for part in ["one", "two", "with_capture"]:
            folder = build / part; folder.mkdir(); (folder / "libEGL.so").write_bytes(part.encode())
        with self.assertRaises(RuntimeError): recipe.artifact(build, "libEGL.so")
        (build / "two/libEGL.so").unlink()
        self.assertEqual(recipe.artifact(build, "libEGL.so"), build / "one/libEGL.so")
        (build / "libEGL.so").write_bytes(b"direct")
        self.assertEqual(recipe.artifact(build, "libEGL.so"), build / "libEGL.so")

    def invoke(self, system="Linux", extra=(), wrong_revision=False, build_error=False, copy_error=False):
        argv = ["build_dependencies.py", "--work-dir", str(self.work), "--output", str(self.output), *extra]
        def checkout(directory, pin, env):
            directory.mkdir(parents=True, exist_ok=True)
            if directory.name == "angle":
                (directory / "third_party/SwiftShader").mkdir(parents=True)
                (directory / "LICENSE").write_text("upstream license\n")
                (directory / "NOTICE-link").symlink_to(directory / "LICENSE")
        def run(argv, *, cwd, env, capture=False):
            command = [str(a) for a in argv]
            if command[:2] == ["git", "rev-parse"]:
                key = "swiftshader" if Path(cwd).name == "SwiftShader" else "angle"
                return "wrong" if wrong_revision else recipe.PINS[key]["commit"]
            if Path(command[0]).name == "autoninja":
                if build_error: raise subprocess.CalledProcessError(1, command)
                build = Path(command[command.index("-C") + 1]); build.mkdir(parents=True)
                suffix = "dylib" if system == "Darwin" else "so"
                for name in [f"libEGL.{suffix}", f"libGLESv2.{suffix}", "libvk_swiftshader.so"]:
                    (build / name).write_bytes(name.encode())
                (build / "vk_swiftshader_icd.json").write_text(json.dumps({"ICD": {"library_path": "/temporary/path.so"}}))
            return None
        with patch("sys.argv", argv), patch.object(recipe.platform, "system", return_value=system), \
             patch.object(recipe.platform, "machine", return_value="arm64"), \
             patch.object(recipe, "checkout", side_effect=checkout), patch.object(recipe, "run", side_effect=run), \
             patch("builtins.print"):
            if copy_error:
                with patch.object(recipe.shutil, "copy2", side_effect=OSError("injected copy failure")): recipe.main()
            else: recipe.main()

    def test_linux_bundle_records_verified_inputs_relative_icd_and_licenses(self):
        self.invoke()
        manifest = json.loads((self.output / "bundle.json").read_text())
        self.assertEqual(manifest["os"], "linux"); self.assertEqual(manifest["arch"], "aarch64")
        self.assertEqual(manifest["angle_commit"], recipe.PINS["angle"]["commit"])
        self.assertEqual(manifest["swiftshader_commit"], recipe.PINS["swiftshader"]["commit"])
        for name, digest in manifest["files"].items():
            self.assertEqual(digest, hashlib.sha256((self.output / name).read_bytes()).hexdigest())
        self.assertEqual(json.loads((self.output / "vk_swiftshader_icd.json").read_text())["ICD"]["library_path"], "./libvk_swiftshader.so")
        self.assertEqual((self.output / "licenses/LICENSE").read_text(), "upstream license\n")
        self.assertFalse((self.output / "licenses/NOTICE-link").exists())
        self.assertFalse(self.output.with_name("bundle.building").exists())
        self.assertIn("pending", manifest["validation"])

    def test_macos_bundle_omits_software_libraries(self):
        self.invoke(system="Darwin")
        files = json.loads((self.output / "bundle.json").read_text())["files"]
        self.assertEqual(set(files), {"libEGL.dylib", "libGLESv2.dylib"})

    def test_output_is_immutable_and_unowned_workspace_is_not_modified(self):
        self.output.mkdir(); sentinel = self.output / "keep"; sentinel.write_text("unchanged")
        with self.assertRaises(SystemExit): self.invoke()
        self.assertEqual(sentinel.read_text(), "unchanged")
        sentinel.unlink(); self.output.rmdir(); self.work.mkdir(); (self.work / "keep").write_text("unchanged")
        with self.assertRaises(SystemExit): self.invoke()
        self.assertEqual((self.work / "keep").read_text(), "unchanged")

    def test_foreign_workspace_pins_and_overlapping_paths_are_rejected(self):
        self.work.mkdir(); owner = self.work / ".obscura-graphics-workspace.json"; owner.write_text('{}')
        with self.assertRaises(SystemExit): self.invoke()
        self.assertEqual(owner.read_text(), '{}')
        owner.unlink(); self.work.rmdir()
        self.output = self.work / "nested"
        with self.assertRaises(SystemExit): self.invoke()
        self.output = self.root / "parent"; self.work = self.output / "nested"
        with self.assertRaises(SystemExit): self.invoke()

    def test_invalid_platform_and_job_count_fail_before_checkout(self):
        for system, extra in [("Windows", ()), ("Linux", ("--jobs", "0")), ("Linux", ("--jobs", "-1"))]:
            with self.subTest(system=system, extra=extra), self.assertRaises(SystemExit): self.invoke(system, extra)
        self.assertFalse(self.work.exists())

    def test_dependency_revision_and_build_failures_never_publish_a_bundle(self):
        for flag in ["wrong_revision", "build_error"]:
            with self.subTest(flag=flag), self.assertRaises((RuntimeError, subprocess.CalledProcessError)):
                self.invoke(**{flag: True})
            self.assertFalse(self.output.exists())

    def test_copy_failure_retains_staging_evidence_without_publishing(self):
        with self.assertRaises(OSError): self.invoke(copy_error=True)
        self.assertFalse(self.output.exists())
        self.assertTrue(self.output.with_name("bundle.building").is_dir())


if __name__ == "__main__":
    unittest.main()
