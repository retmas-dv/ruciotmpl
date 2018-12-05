__author__ = 'Dmitry Golubkov'

# howTo install Rucio client
# source env/bin/activate
# pip install rucio-clients-atlas
# copy configuration

# using:
# >>> from ruciotmpl import DDMWrapper
# >>> ddm = DDMWrapper()
# >>> ddm.ddm_list_datasets_in_container(name)

import os
import sys
import re
import logging
from rucio.client import Client
from rucio.common.exception import CannotAuthenticate, DataIdentifierNotFound, RucioException

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger()

DDM_ACCOUNT_NAME = 'prodsys'
X509_PROXY_PATH = '~/proxy'


def ddm_exception_free_wrapper(func):
    def call(*args, **kwargs):
        status = {'exception': None, 'result': None}
        try:
            result = func(*args, **kwargs)
            status['result'] = result
        except RucioException as ex:
            status['exception'] = str(ex)
        return status

    return call


class DDMWrapper(object):
    def __init__(self):
        try:
            # set up Rucio environment
            os.environ['RUCIO_ACCOUNT'] = DDM_ACCOUNT_NAME
            os.environ['RUCIO_AUTH_TYPE'] = 'x509_proxy'
            os.environ['X509_USER_PROXY'] = self._get_proxy()
            self.ddm_client = Client()
        except CannotAuthenticate as ex:
            logger.critical('DDM: authentication failed: {0}'.format(str(ex)))
        except Exception as ex:
            logger.critical('DDM: initialization failed: {0}'.format(str(ex)))

    @staticmethod
    def _get_proxy():
        return X509_PROXY_PATH

    def verify(self):
        try:
            rucio_server_info = self.ddm_client.ping()
            rucio_user_info = self.ddm_client.whoami()
            if rucio_server_info and rucio_user_info:
                logger.info('DDM: Rucio server version is {0}'.format(rucio_server_info['version']))
                logger.info('DDM: Current user is {0} (status = {1})'.format(
                    rucio_user_info['account'], rucio_user_info['status']))
                return True
            else:
                return False
        except Exception as ex:
            logger.exception('DDM: exception occurred during verifying: {0}'.format(str(ex)))
            return False

    @staticmethod
    def extract_scope(dsn):
        if dsn.find(':') > -1:
            return dsn.split(':')[0], dsn.split(':')[1]
        else:
            scope = dsn.split('.')[0]
            if dsn.startswith('user') or dsn.startswith('group'):
                scope = '.'.join(dsn.split('.')[0:2])
            return scope, dsn

    @ddm_exception_free_wrapper
    def ddm_list_datasets(self, pattern):
        result = list()
        match = re.match(r'^\*', pattern)
        if not match:
            scope, dataset = self.extract_scope(pattern)
            collection = 'dataset'
            if dataset.endswith('/'):
                dataset = dataset[:-1]
                collection = 'container'
            filters = {'name': dataset}
            # FIXME: use type='collection'
            for name in self.ddm_client.list_dids(scope, filters, type=collection):
                result.append('{0}:{1}'.format(scope, name))
        return result

    @ddm_exception_free_wrapper
    def ddm_list_datasets_in_container(self, container):
        dataset_names = list()

        if container.endswith('/'):
            container = container[:-1]

        scope, container_name = self.extract_scope(container)

        try:
            if self.ddm_client.get_metadata(scope, container_name)['did_type'] == 'CONTAINER':
                for e in self.ddm_client.list_content(scope, container_name):
                    dsn = '{0}:{1}'.format(e['scope'], e['name'])
                    if e['type'] == 'DATASET':
                        dataset_names.append(dsn)
                    elif e['type'] == 'CONTAINER':
                        names = self.ddm_list_datasets_in_container(dsn)['result']
                        # FIXME: check not exist
                        dataset_names.extend(names)
        except DataIdentifierNotFound:
            # FIXME
            pass
        return dataset_names

    @ddm_exception_free_wrapper
    def ddm_list_files_in_dataset(self, dsn):
        filename_list = list()
        scope, dataset = self.extract_scope(dsn)
        files = self.ddm_client.list_files(scope, dataset, long=False)
        for file_name in [e['name'] for e in files]:
            filename_list.append(file_name)
        return filename_list

    @ddm_exception_free_wrapper
    def ddm_get_number_files(self, dsn):
        number_files = 0
        scope, dataset = self.extract_scope(dsn)
        files = self.ddm_client.list_files(scope, dataset, long=False)
        for e in files:
            number_files += 1
        return number_files

    @ddm_exception_free_wrapper
    def ddm_get_number_events(self, dsn):
        scope, dataset = self.extract_scope(dsn)
        metadata = self.ddm_client.get_metadata(scope=scope, name=dataset)
        return int(metadata['events'] or 0)

    @ddm_exception_free_wrapper
    def ddm_erase(self, dsn, undo=False):
        scope, name = self.extract_scope(dsn)
        lifetime = 86400
        if undo:
            lifetime = None
        self.ddm_client.set_metadata(scope=scope, name=name, key='lifetime', value=lifetime)

    @ddm_exception_free_wrapper
    def ddm_register_dataset(self, dsn, files=None, statuses=None, meta=None, lifetime=None):
        """
        :param dsn: the DID name
        :param files: list of file names
        :param statuses: dictionary with statuses, like {'monotonic':True}.
        :param meta: meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
        :param lifetime: DID's lifetime (in seconds).
        """
        scope, name = self.extract_scope(dsn)
        dids = None
        if files:
            dids = list()
            for file_ in files:
                file_scope, file_name = self.extract_scope(file_)
                dids.append({'scope': file_scope, 'name': file_name})
        self.ddm_client.add_dataset(scope, name, statuses=statuses, meta=meta, lifetime=lifetime, files=dids)

    @ddm_exception_free_wrapper
    def ddm_register_files_in_dataset(self, dsn, files):
        scope, name = self.extract_scope(dsn)
        dids = list()
        for file_ in files:
            file_scope, file_name = self.extract_scope(file_)
            dids.append({'scope': file_scope, 'name': file_name})
        self.ddm_client.attach_dids(scope, name, dids)

    @ddm_exception_free_wrapper
    def ddm_register_container(self, dsn, datasets=None):
        if dsn.endswith('/'):
            dsn = dsn[:-1]
        scope, name = self.extract_scope(dsn)
        self.ddm_client.add_container(scope=scope, name=name)
        if datasets:
            dsns = list()
            for dataset in datasets:
                dataset_scope, dataset_name = self.extract_scope(dataset)
                dsns.append({'scope': dataset_scope, 'name': dataset_name})
            self.ddm_client.add_datasets_to_container(scope=scope, name=name, dsns=dsns)

    @ddm_exception_free_wrapper
    def ddm_register_datasets_in_container(self, dsn, datasets):
        if dsn.endswith('/'):
            dsn = dsn[:-1]
        scope, name = self.extract_scope(dsn)
        dsns = list()
        for dataset in datasets:
            dataset_scope, dataset_name = self.extract_scope(dataset)
            dsns.append({'scope': dataset_scope, 'name': dataset_name})
        self.ddm_client.add_datasets_to_container(scope=scope, name=name, dsns=dsns)

    @ddm_exception_free_wrapper
    def ddm_delete_datasets_from_container(self, dsn, datasets):
        if dsn.endswith('/'):
            dsn = dsn[:-1]
        scope, name = self.extract_scope(dsn)
        dsns = list()
        for dataset in datasets:
            dataset_scope, dataset_name = self.extract_scope(dataset)
            dsns.append({'scope': dataset_scope, 'name': dataset_name})
        self.ddm_client.detach_dids(scope=scope, name=name, dids=dsns)

    @ddm_exception_free_wrapper
    def ddm_get_metadata_attribute(self, dsn, attribute_name):
        scope, dataset = self.extract_scope(dsn)
        metadata = self.ddm_client.get_metadata(scope=scope, name=dataset)
        if attribute_name in metadata.keys():
            return metadata[attribute_name]
        else:
            return None

    @ddm_exception_free_wrapper
    def ddm_get_full_replicas(self, dsn):
        datasets = list()
        dataset_replicas = dict()
        if self.is_dataset_container(dsn):
            datasets.extend(self.ddm_list_datasets_in_container(dsn)['result'])
        else:
            datasets.append(dsn)
        for dataset in datasets:
            dataset_scope, dataset_name = self.extract_scope(dataset)
            for dataset_replica in self.ddm_client.list_dataset_replicas(dataset_scope, dataset_name):
                if dataset_replica['available_length'] == dataset_replica['length']:
                    if dataset not in dataset_replicas.keys():
                        dataset_replicas[dataset] = list()
                    dataset_replicas[dataset].append(dataset_replica['rse'])
        return list(set.intersection(*[set(dataset_replicas[key]) for key in dataset_replicas]))

    def is_dataset_container(self, dsn):
        scope, dataset = self.extract_scope(dsn)
        metadata = self.ddm_client.get_metadata(scope=scope, name=dataset)
        return bool(metadata['did_type'] == 'CONTAINER')

    def get_nevents_per_file(self, dsn):
        number_files = self.ddm_get_number_files(dsn)['result']
        if not number_files:
            raise ValueError('Dataset {0} has no files'.format(dsn))
        number_events = self.ddm_get_number_events(dsn)['result']
        if not number_files:
            raise ValueError('Dataset {0} has no events or corresponding metadata (nEvents)'.format(dsn))
        round_up = lambda num: int(num + 1) if int(num) != num else int(num)
        return round_up(float(number_events) / float(number_files))

    def get_datasets_and_containers(self, input_data_name, datasets_contained_only=False):
        data_dict = {'containers': list(), 'datasets': list()}

        if input_data_name[-1] == '/':
            input_container_name = input_data_name
            input_data_name = input_data_name[:-1]
        else:
            input_container_name = '{0}/'.format(input_data_name)

        # searching containers first
        for name in self.ddm_list_datasets(input_container_name)['result']:
            if self.is_dataset_container(name):
                if name[-1] == '/':
                    data_dict['containers'].append(name)
                else:
                    data_dict['containers'].append('{0}/'.format(name))

        # searching datasets
        if datasets_contained_only and len(data_dict['containers']):
            for container_name in data_dict['containers']:
                dataset_names = self.ddm_list_datasets_in_container(container_name)['result']
                data_dict['datasets'].extend(dataset_names)
        else:
            for name in self.ddm_list_datasets("{0}*".format(input_data_name))['result']:
                # FIXME
                is_sub_dataset = \
                    re.match(r"%s.*_(sub|dis)\d*" % input_data_name.split(':')[-1], name.split(':')[-1], re.IGNORECASE)
                is_o10_dataset = \
                    re.match(r"%s.*.o10$" % input_data_name.split(':')[-1], name.split(':')[-1], re.IGNORECASE)
                if not self.is_dataset_container(name) and not is_sub_dataset and not is_o10_dataset:
                    data_dict['datasets'].append(name)

        return data_dict


if __name__ == '__main__':
    pass
