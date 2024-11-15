import pytest
import requests
import json
import logging

class Const:
    BASE_URL = 'https://viz.aqa.luntry.com/api/v1'
    API_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImI5NjgzZTkzLTAxZDEtNDYwOS1iYTg2LWY3ZDNmMGFhYzdkOSIsImlhdCI6MTczMTYxNzc3MywiZXhwIjoxNzM5MzkzNzczfQ.CRnB06FIJo_evMqYvpLV2nzbRb5l-l8-jCxOs5wL24c'
    CLUSTER_ID = '4aa5b484-df96-4f5b-b9de-7ee6fdc9f002'
    APP_NAME = 'registry.luntry.com/luntry/vuln-op'
    FILE_SBOM_EXAMPLE = 'sbom_report.json'
    DIR_TEST_DATA = '/home/ech20/test/job_luntry/test_data'

class Common_Vars:
    image_digest = 'empty'
    sbom_release_id = 'empty'
    sbom_content = 'empty'
    sbom_releases = []
    sbom_release_single = []

class Tools:
    @staticmethod
    def create_model_sbom_from_file_by_id(path_to_sbom_releases_file, release_id) ->  list:
        #path_to_sbom_releases_file = f"{Const.DIR_TEST_DATA}/{Const.FILE_SBOM_EXAMPLE}"
        with open(path_to_sbom_releases_file, 'r') as file:
            sbom_releases = json.load(file)

        release_single = []
        for component in sbom_releases:
            if component['sbomId'] == release_id:
                release_single.append(component)

        return release_single

    @staticmethod
    def compare_sboms(sbom_actual: list, sbom_expected: list) -> bool:
        hash_dict = lambda d: hash(frozenset(d.items()))
        hashed_sbom_actual = {hash_dict(component) for component in sbom_actual}
        hashed_sbom_expected = {hash_dict(component) for component in sbom_expected}

        return hashed_sbom_actual == hashed_sbom_expected



class Tests: 
    def atest_read_json_from_file(self):
        file_json = f"{Const.DIR_TEST_DATA}/{Const.FILE_SBOM_EXAMPLE}"
        # Open and read the JSON file
        with open(file_json, 'r') as file:
            sbom_releases = json.load(file)
            


        #return JSON (list of dicts)
        Common_Vars.sbom_releases = sbom_releases

        # Print the data
        #print(Common_Vars.sbom_releases)

    def atest_create_sbom_from_releases_by_id(self):
        id = Common_Vars.sbom_release_id
        releases = Common_Vars.sbom_releases
        release_single = []
        for component in releases:
            if component['sbomId'] == id:
                release_single.append(component)

        #return JSON (list of dicts)
        Common_Vars.sbom_release_single = release_single

    def atest_compare_lists(self, list_first, list_second):
        '''
        [
            {'sbomId': '26', 'version': 'v2.120.1', 'package': 'k8s.io/klog/v2'}, 
            {'sbomId': '26', 'version': 'v1.6.0', 'package': 'modernc.org/mathutil'}, 
            {'sbomId': '26', 'version': '2024a-0+deb12u1', 'package': 'tzdata'}
        ]
        ''' 
        
        lst1 = [
            {'sbomId': '26', 'version': 'v2.120.1', 'package': 'k8s.io/klog/v2'}, 
            {'sbomId': '26', 'version': 'v1.6.0', 'package': 'modernc.org/mathutil'}, 
            {'sbomId': '26', 'version': '2024a-0+deb12u1', 'package': 'tzdata'}
        ]

        lst2 = [
            {'sbomId': '26', 'version': 'v1.6.0', 'package': 'modernc.org/mathutil'}, 
            {'sbomId': '26', 'version': 'v2.120.1', 'package': 'k8s.io/klog/v2'}, 
            {'sbomId': '26', 'version': '2024a-0+deb12u1', 'package': 'tzdata'}
        ]

        hashed1 = {hash(frozenset(d.items())) for d in lst1}
        hashed2 = {hash_dict(d) for d in lst2}
        diff = (hashed1 == hashed2)
        print(diff)

 



    @pytest.mark.dependency(name="get_image_digest")
    def test_get_image_digest(self):
        #pre
        url = f'{Const.BASE_URL}/images/runtime'

        rq_params = {
            'clusterId': Const.CLUSTER_ID, 
            'applicationName': Const.APP_NAME, 
            'usedImages':'true'
        }

        rq_headers = {
            'x-access-token': Const.API_TOKEN
        }

        #do
        response = requests.get(url, verify=False, params = rq_params, headers = rq_headers)
        response.raise_for_status()

        #process
        json_response = response.json()
        Common_Vars.image_digest = json_response[0]['digest']
        logging.info(f"image_digest: {Common_Vars.image_digest}")

        #check
        assert response.status_code == 200


    @pytest.mark.dependency(name="get_sbom_id_by_image_digest", depends=["get_image_digest"])
    def test_get_sbom_id_by_image_digest(self):
        #pre
        url = f'{Const.BASE_URL}/sbom/by-digest'

        rq_params = {
            'digest': Common_Vars.image_digest
        }

        rq_headers = {
            'x-access-token': Const.API_TOKEN
        }

        #do
        response = requests.get(url, verify=False, params = rq_params, headers = rq_headers)
        response.raise_for_status()

        #process_and_cleanup
        json_response = response.json()
        Common_Vars.sbom_release_id = json_response[0]['id']
        logging.info(f"sbom_id: {Common_Vars.sbom_release_id}")

        #check
        assert response.status_code == 200

        
    @pytest.mark.dependency(name="get_sbom_components_by_id", depends=["get_sbom_id_by_image_digest"])
    def test_get_sbom_components_by_id(self):
        #pre
        url = f'{Const.BASE_URL}/sbom/components'

        rq_params = {
            'id': Common_Vars.sbom_release_id
        }

        rq_headers = {
            'x-access-token': Const.API_TOKEN
        }

        #do
        response = requests.get(url, verify=False, params = rq_params, headers = rq_headers)
        response.raise_for_status()

        #process_and_cleanup
        json_response = response.json()
        #Common_Vars.sbom_content = json_response
        #logging.info(f"sbom_content: {Common_Vars.sbom_content}")

        sbom_actual = json_response
        path_to_sbom_releases_file = f"{Const.DIR_TEST_DATA}/{Const.FILE_SBOM_EXAMPLE}"
        sbom_expected = Tools.create_model_sbom_from_file_by_id(path_to_sbom_releases_file, Common_Vars.sbom_release_id)

        #check
        assert response.status_code == 200
        assert Tools.compare_sboms(sbom_actual, sbom_expected), "Actual sbom is not equal to expected sbom"


    

    