import json
import os

import pytest

from lib4sbom.cyclonedx.cyclonedx_parser import CycloneDXParser as test_module


class TestCcycloneDX_parser:
    def get_test_filepath(self, relpath):
        file_path = os.path.abspath(os.path.realpath(__file__))
        test_data_path = os.path.join(os.path.dirname(file_path), "data")
        return os.path.join(test_data_path, relpath)

    def test_parse(self):
        assert False

    def test_parse_cyclonedx_json(self):
        assert False

    def test_parse_cyclonedx_xml(self):
        test_parser = test_module()
        path = self.get_test_filepath('hadoop-aliyun-3.4.1-cyclonedx.xml')
        result = test_parser.parse(path)
        (
            cyclonedx_document,
            files,
            packages,
            relationships,
            vulnerabilities,
            services,
            licenses
        ) = result

        with open(path, "r", encoding="utf-8") as f:
            sbom_string = f.read()
        result = test_parser.parse(path, sbom_string)
        (
            cyclonedx_document,
            files,
            packages,
            relationships,
            vulnerabilities,
            services,
            licenses
        ) = result

    def test_parse_cyclonedx_multiple_licenses_json(self):
        test_parser = test_module()
        path = self.get_test_filepath("testapp2.json")
        result1 = test_parser.parse(path)
        with open(path, "r", encoding="utf-8") as f:
            sbom_string = f.read()
        result2 = test_parser.parse(path, sbom_string)
        for result in [result1, result2]:
            (
                cyclonedx_document,
                files,
                packages,
                relationships,
                vulnerabilities,
                services,
            ) = result
            multi_license = None
            for p, v in packages:
                if p == "multi-license":
                    multi_license = packages[(p, v)]
                    break

            assert multi_license is not None, "Did not find expected package multi-license"
            assert "licenselist" in multi_license
            license_list = multi_license["licenselist"]
            assert len(license_list) == 2
            assert license_list[0]["license"]["id"] == "MIT"
            assert license_list[1]["license"]["id"] == "Apache-2.0"

    def test_parse_cyclonedx_multiple_affects_json(self):
        # A vulnerability with multiple affects entries produces one record
        # per affected component (issue #99)
        test_parser = test_module()
        path = self.get_test_filepath("one-vuln-two-affects.cdx.json")
        with open(path, "r", encoding="utf-8") as sbom_file:
            sbom_string = sbom_file.read()
        result = test_parser.parse(sbom_string)
        vulnerabilities = result["vulnerabilities"]
        assert len(vulnerabilities) == 2
        bom_links = sorted(record["bom_link"] for record in vulnerabilities)
        bom_ref_base = (
            "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#"
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@"
        )
        assert bom_links == sorted(
            bom_ref_base + version for version in ("2.9.8", "2.9.9")
        )
        for record in vulnerabilities:
            assert record["id"] == "CVE-2019-12384"
            assert record["status"] == "not_affected"
            assert record["justification"] == "code_not_present"

    def test_parse_cyclonedx_affects_layouts_equivalent(self):
        # One vulnerability object with multiple affects entries provides the
        # same affected component records as one vulnerability object per
        # affected component, each with a single affects entry
        test_parser = test_module()
        records = []
        for test_file in (
            "one-vuln-two-affects.cdx.json",
            "two-vulns-one-affects.cdx.json",
        ):
            path = self.get_test_filepath(test_file)
            with open(path, "r", encoding="utf-8") as sbom_file:
                sbom_string = sbom_file.read()
            result = test_parser.parse(sbom_string)
            affected = {
                record["bom_link"]: (
                    record["id"],
                    record["status"],
                    record["justification"],
                )
                for record in result["vulnerabilities"]
            }
            records.append(affected)
        assert records[0] == records[1]
        assert len(records[0]) == 2

    def test_parse_cyclonedx_affects_versions_list_json(self):
        # The CycloneDX specification defines affects[].versions as a list of
        # version objects, with one record per affected version
        sbom_string = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-0001",
                        "affects": [
                            {
                                "ref": "component-a",
                                "versions": [{"version": "1.0"}, {"version": "2.0"}],
                            },
                        ],
                    }
                ],
            }
        )
        test_parser = test_module()
        result = test_parser.parse(sbom_string)
        vulnerabilities = result["vulnerabilities"]
        assert len(vulnerabilities) == 2
        releases = sorted(record["release"] for record in vulnerabilities)
        assert releases == ["1.0", "2.0"]
        for record in vulnerabilities:
            assert record["bom_link"] == "component-a"
            assert record["id"] == "CVE-2026-0001"

    def test_parse_cyclonedx_affects_single_version_json(self):
        # An affects entry with a single version produces one record for that
        # affected component and version
        sbom_string = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-0001",
                        "affects": [
                            {"ref": "component-a", "versions": [{"version": "1.0"}]},
                        ],
                    }
                ],
            }
        )
        test_parser = test_module()
        result = test_parser.parse(sbom_string)
        vulnerabilities = result["vulnerabilities"]
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["bom_link"] == "component-a"
        assert vulnerabilities[0]["release"] == "1.0"

    def test_parse_cyclonedx_vulnerability_no_affects_json(self):
        # A vulnerability without an affects entry still produces a record
        sbom_string = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-0001",
                        "source": {"name": "NVD"},
                    }
                ],
            }
        )
        test_parser = test_module()
        result = test_parser.parse(sbom_string)
        vulnerabilities = result["vulnerabilities"]
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["id"] == "CVE-2026-0001"
        assert "bom_link" not in vulnerabilities[0]

    def test_parse_cyclonedx_vulnerability_empty_affects_json(self):
        # A vulnerability with an empty affects list produces one record
        # without an error
        sbom_string = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-0001",
                        "affects": [],
                    }
                ],
            }
        )
        test_parser = test_module()
        result = test_parser.parse(sbom_string)
        vulnerabilities = result["vulnerabilities"]
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["id"] == "CVE-2026-0001"
        assert "bom_link" not in vulnerabilities[0]
