import pytest
import requests
import json
import logging


class Const:
    BASE_URL = "https://viz.aqa.luntry.com/api/v1"
    API_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImI5NjgzZTkzLTAxZDEtNDYwOS1iYTg2LWY3ZDNmMGFhYzdkOSIsImlhdCI6MTczMTYxNzc3MywiZXhwIjoxNzM5MzkzNzczfQ.CRnB06FIJo_evMqYvpLV2nzbRb5l-l8-jCxOs5wL24c"
    CLUSTER_ID = "4aa5b484-df96-4f5b-b9de-7ee6fdc9f002"
    APP_NAME = "registry.luntry.com/luntry/vuln-op"
    FILE_SBOM_EXAMPLE = "sbom_report.json"
    DIR_TEST_DATA = "/home/ech20/test/job_luntry/test_data"


class CommonVars:
    image_digest = "empty"
    sbom_release_id = "empty"
    sbom_content = "empty"
    sbom_releases = []
    sbom_release_single = []


class Tools:
    @staticmethod
    def create_sbom_release_from_file_by_release_id(path_to_sbom_releases_file, release_id) -> list:
        with open(path_to_sbom_releases_file, "r") as file:
            sbom_releases = json.load(file)

        sbom_release_single = []
        for component in sbom_releases:
            if component["sbomId"] == release_id:
                sbom_release_single.append(component)

        return sbom_release_single

    @staticmethod
    def compare_sboms(sbom_actual: list, sbom_expected: list) -> bool:
        hash_dict = lambda d: hash(frozenset(d.items()))
        hashed_sbom_actual = {hash_dict(component) for component in sbom_actual}
        hashed_sbom_expected = {hash_dict(component) for component in sbom_expected}

        return hashed_sbom_actual == hashed_sbom_expected


class Tests:
    @pytest.mark.dependency(name="get_image_digest")
    def test_get_image_digest(self):
        # pre
        url = f"{Const.BASE_URL}/images/runtime"

        rq_params = {
            "clusterId": Const.CLUSTER_ID,
            "applicationName": Const.APP_NAME,
            "usedImages": "true",
        }

        rq_headers = {"x-access-token": Const.API_TOKEN}

        # do
        response = requests.get(url, verify=False, params=rq_params, headers=rq_headers)
        response.raise_for_status()

        # process
        json_response = response.json()
        CommonVars.image_digest = json_response[0]["digest"]
        logging.info(f"image_digest: {CommonVars.image_digest}")

        # check
        assert response.status_code == 200

    @pytest.mark.dependency(name="get_sbom_id_by_image_digest", depends=["get_image_digest"])
    def test_get_sbom_id_by_image_digest(self):
        # pre
        url = f"{Const.BASE_URL}/sbom/by-digest"

        rq_params = {"digest": CommonVars.image_digest}

        rq_headers = {"x-access-token": Const.API_TOKEN}

        # do
        response = requests.get(url, verify=False, params=rq_params, headers=rq_headers)
        response.raise_for_status()

        # process
        json_response = response.json()
        CommonVars.sbom_release_id = json_response[0]["id"]
        logging.info(f"sbom_id: {CommonVars.sbom_release_id}")

        # check
        assert response.status_code == 200

    @pytest.mark.dependency(name="get_sbom_components_by_id", depends=["get_sbom_id_by_image_digest"])
    def test_get_sbom_components_by_id(self):
        # pre
        url = f"{Const.BASE_URL}/sbom/components"

        rq_params = {"id": CommonVars.sbom_release_id}

        rq_headers = {"x-access-token": Const.API_TOKEN}

        # do
        response = requests.get(url, verify=False, params=rq_params, headers=rq_headers)
        response.raise_for_status()

        # process
        sbom_actual = response.json()
        path_to_sbom_releases_file = f"{Const.DIR_TEST_DATA}/{Const.FILE_SBOM_EXAMPLE}"
        sbom_expected = Tools.create_sbom_release_from_file_by_release_id(
            path_to_sbom_releases_file, CommonVars.sbom_release_id
        )

        # check
        assert response.status_code == 200
        assert Tools.compare_sboms(sbom_actual, sbom_expected), "Actual sbom is not equal to expected sbom"
        logging.info("Actual sbom is equal to expected sbom")
