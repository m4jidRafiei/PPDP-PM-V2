import shutil
import sys
from django.shortcuts import render
from django.conf import settings
import os
from os import listdir, path
from os.path import isfile, join
from datetime import datetime
from django.http import HttpResponseRedirect, HttpResponse
from wsgiref.util import FileWrapper
import json
import time
import traceback
from django.core.files.storage import FileSystemStorage

from pm4py.objects.log.importer.xes import factory as xes_importer
from pm4py.objects.log.exporter.xes import factory as xes_exporter
from p_privacy_qt.SMS import SMS
from p_privacy_qt.EMD import EMD


def privacy_analysis_main(request):
    paSettings = settings.PRIVACY_ANALYSIS

    event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")

    event_log = getXesLogPath(paSettings["EVENT_LOG_NAME_1"])
    event_log_backup = getXesLogPath(paSettings["EVENT_LOG_NAME_2"])

    eventlogs = [f for f in listdir(event_logs_path) if isfile(join(event_logs_path, f))]

    logEventAttributes = []
    logBackupEventAttributes = []
    if(event_log not in [':notset:', None]):
        eLog = xes_importer.apply(event_log)
        logEventAttributes = [a for a in eLog[0][0].keys()]
    if(event_log_backup not in [':notset:', None]):
        eLog = xes_importer.apply(event_log_backup)
        logBackupEventAttributes = [a for a in eLog[0][0].keys()]

    returnObject = {'eventlog_list': eventlogs, 'disclosureRiskActive': "active", 'dataUtilityActive': '', 'logEventAttributes': logEventAttributes, 'logBackupEventAttributes': logBackupEventAttributes}
    returnObject['log_name'] = paSettings["EVENT_LOG_NAME_1"]
    returnObject['log_name_backup'] = paSettings["EVENT_LOG_NAME_2"]
    returnObject['logLifecycles'] = paSettings["EVENT_LOG_LIFECYCLES_1"]
    returnObject['logBackupLifecycles'] = paSettings["EVENT_LOG_LIFECYCLES_2"]

    if request.method == 'POST':
        print(request.POST)

        if("actionDataUtility" in request.POST):
            returnObject['dataUtilityActive'] = "active"
            returnObject['disclosureRiskActive'] = ""

        if request.is_ajax():
            return render(request, 'privacy_analysis.html', returnObject)
        else:
            if "uploadButton" in request.POST:
                if "event_log" not in request.FILES:
                    return HttpResponseRedirect(request.path_info)

                log = request.FILES["event_log"]
                fs = FileSystemStorage(event_logs_path)
                filename = fs.save(log.name, log)
                uploaded_file_url = fs.url(filename)

                returnObject['eventlog_list'] = [f for f in listdir(event_logs_path) if isfile(join(event_logs_path, f))]

                return render(request, 'privacy_analysis.html', returnObject)

            elif "deleteButton" in request.POST:  # for event logs
                if "log_list" not in request.POST:
                    return HttpResponseRedirect(request.path_info)

                filename = request.POST["log_list"]
                if paSettings["EVENT_LOG_NAME_1"] == filename:
                    paSettings["EVENT_LOG_NAME_1"] = ":notset:"

                eventlogs = [f for f in listdir(event_logs_path) if isfile(join(event_logs_path, f))]

                eventlogs.remove(filename)
                file_dir = os.path.join(event_logs_path, filename)
                os.remove(file_dir)

                returnObject['eventlog_list'] = eventlogs

                return render(request, 'privacy_analysis.html', returnObject)

            elif "setButton" in request.POST or "setButtonBackup" in request.POST:
                if "log_list" not in request.POST:
                    return HttpResponseRedirect(request.path_info)

                filename = request.POST["log_list"]
                eLog = xes_importer.apply(getXesLogPath(filename))

                if "setButton" in request.POST:
                    paSettings["EVENT_LOG_NAME_1"] = filename
                    returnObject['logEventAttributes'] = [a for a in eLog[0][0].keys()]
                    paSettings["EVENT_LOG_LIFECYCLES_1"] = getUniqueLifecycles(eLog)

                elif "setButtonBackup" in request.POST:
                    paSettings["EVENT_LOG_NAME_2"] = filename
                    returnObject['logBackupEventAttributes'] = [a for a in eLog[0][0].keys()]
                    paSettings["EVENT_LOG_LIFECYCLES_2"] = getUniqueLifecycles(eLog)

                returnObject['eventlog_list'] = [f for f in listdir(event_logs_path) if isfile(join(event_logs_path, f))]
                returnObject['log_name'] = paSettings["EVENT_LOG_NAME_1"]
                returnObject['log_name_backup'] = paSettings["EVENT_LOG_NAME_2"]
                returnObject['logLifecycles'] = paSettings["EVENT_LOG_LIFECYCLES_1"]
                returnObject['logBackupLifecycles'] = paSettings["EVENT_LOG_LIFECYCLES_2"]
                return render(request, 'privacy_analysis.html', returnObject)

            elif "downloadButton" in request.POST:  # for event logs
                if "log_list" not in request.POST:
                    return HttpResponseRedirect(request.path_info)

                filename = request.POST["log_list"]
                file_dir = os.path.join(event_logs_path, filename)

                try:
                    wrapper = FileWrapper(open(file_dir, 'rb'))
                    response = HttpResponse(wrapper, content_type='application/force-download')
                    response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_dir)
                    return response
                except Exception as e:
                    return None
            else:
                return render(request, 'privacy_analysis.html', returnObject)
    else:
        if request.is_ajax():
            if(request.GET['analysis'] == 'dataUtility'):
                reqConfData = json.loads(getRequestParameter(request.GET, 'data', '{}'))
                print(getDataUtilitySettings(reqConfData))

                # Total data utility
                print("1")
                utility = getDataUtilityValue(event_log, event_log_backup, getDataUtilitySettings(reqConfData))
                print("7")
                return HttpResponse(json.dumps({"Utility": utility}), content_type='application/json')

            elif(request.GET['analysis'] == 'disclosureRisk'):
                reqConfData = json.loads(getRequestParameter(request.GET, 'data', '{}'))
                print(getDisclosureRiskSettings(reqConfData))

                rv_cd, rv_td = getRiskValue(event_log, getDisclosureRiskSettings(reqConfData))
                return HttpResponse(json.dumps({"Risk": {"cd": rv_cd, "td": rv_td}}), content_type='application/json')
        else:
            returnObject['logLifecycles'] = getRequestParameter(request.GET, 'logLifecycles', [])
            returnObject['logBackupLifecycles'] = getRequestParameter(request.GET, 'logBackupLifecycles', [])

        return render(request, 'privacy_analysis.html', returnObject)


def getXesLogPath(logName):
    if(logName == ':notset:'):
        return None

    event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")
    event_log = os.path.join(event_logs_path, logName)
    return event_log


def getDataUtilityValue(origLogPath, privLogPath, settings):
    sys.stdout = open(os.devnull, 'w')

    sensitive = []
    time_accuracy = settings['DU_TimeAccuracy'].lower()  # original, seconds, minutes, hours, days
    event_attributes = list(set(settings['DU_EventAttributes']))  # Make list unique
    # these life cycles are applied only when all_lif_cycle = False
    life_cycle = ['complete', '', 'COMPLETE']#list(set(settings['DU_LifeCycle']))  # Make list unique
    # when life cycle is in trace attributes then all_life_cycle has to be True
    all_life_cycle = settings['DU_IsAllLifeCycle']

    original_log = xes_importer.apply(origLogPath)
    privacy_log = xes_importer.apply(privLogPath)
    from_same_origin = settings['DU_IsFromSameOrigin']  # when both event logs drived from the same original event logs

 
    sms = SMS()
    logsimple, traces, sensitives = sms.create_simple_log_adv(original_log,event_attributes,life_cycle,all_life_cycle,sensitive,time_accuracy)
    logsimple_2, traces_2, sensitives_2 = sms.create_simple_log_adv(privacy_log,event_attributes,life_cycle,all_life_cycle,sensitive,time_accuracy)

    #log 1 convert to char
    map_dict_act_chr,map_dict_chr_act = sms.map_act_char(traces,0)
    simple_log_char_1 = sms.convert_simple_log_act_to_char(traces,map_dict_act_chr)

    #log 2 convert to char
    if from_same_origin: #use the same mapping
        simple_log_char_2 = sms.convert_simple_log_act_to_char(traces_2,map_dict_act_chr)
    else:
        map_dict_act_chr_2,map_dict_chr_act_2 = sms.map_act_char(traces_2,len(traces)+2)
        simple_log_char_2 = sms.convert_simple_log_act_to_char(traces_2,map_dict_act_chr_2)

    start_time = time.time()

    my_emd = EMD()
    # log_freq_1, log_only_freq_1 = my_emd.log_freq(traces)
    # log_freq_2 , log_only_freq_2 = my_emd.log_freq(traces_2)

    log_freq_1, log_only_freq_1 = my_emd.log_freq(simple_log_char_1)
    log_freq_2 , log_only_freq_2 = my_emd.log_freq(simple_log_char_2)

    cost_lp = my_emd.emd_distance_pyemd(log_only_freq_1,log_only_freq_2,log_freq_1,log_freq_2)
    # cost_lp = my_emd.emd_distance(log_freq_1,log_freq_2)

    data_utility = 1 - cost_lp

    sys.stdout = sys.__stdout__
    return data_utility


def getRiskValue(event_log, settings):
    print(settings)

    existence_based = settings['DR_IsExistenceBased']  # it is faster when there is no super long traces in the event log
    measurement_type = settings['DR_MeasureType'].lower()  # average or worst_case
    sensitive = []
    # is needed only when time is included in the event_attributes
    time_accuracy = settings['DR_TimeAccuracy'].lower()  # original, seconds, minutes, hours, days
    event_attributes = list(set(settings['DR_EventAttributes']))  # Make list unique
    # these life cycles are applied only when all_lif_cycle = False
    life_cycle = list(set(settings['DR_LifeCycle']))  # Make list unique
    # when life cycle is in trace attributes then all_life_cycle has to be True
    all_life_cycle = settings['DR_IsAllLifeCycle']

    log = xes_importer.apply(event_log)

    bk_type = settings['DR_BKType'].lower()  # set,multiset,sequence
    bk_length = settings['DR_BKSizePower']  # int

    sms = SMS()
    # simple_log = sms.create_simple_log(log,["concept:name", "lifecycle:transition"])
    logsimple, traces, sensitives = sms.create_simple_log_adv(log, event_attributes, life_cycle, all_life_cycle, sensitive, time_accuracy)

    map_dict_act_chr, map_dict_chr_act = sms.map_act_char(traces,0)
    simple_log_char_1 = sms.convert_simple_log_act_to_char(traces, map_dict_act_chr)

    sms.set_simple_log(simple_log_char_1)

    multiset_log = sms.get_multiset_log_n(simple_log_char_1)

    # multiset_log1 = sms.get_multiset_log(simple_log)

    uniq_act = sms.get_unique_elem(simple_log_char_1)

    start_time = time.time()

    # min_len = min(len(uniq_act),3)

    return sms.disclosure_calc(bk_type, uniq_act, measurement_type, bk_length, existence_based, simple_log_char_1, multiset_log)


def getDisclosureRiskSettings(requestData):
    return {
        'DR_IsExistenceBased': getRequestParameter(requestData, 'DR_IsExistenceBased', True),
        'DR_IsAllLifeCycle': getRequestParameter(requestData, 'DR_IsAllLifeCycle', True),
        'DR_MeasureType': getRequestParameter(requestData, 'DR_MeasureType', 'average'),
        'DR_EventAttributes': getRequestParameter(requestData, 'DR_EventAttributes', []),
        'DR_TimeAccuracy': getRequestParameter(requestData, 'DR_TimeAccuracy', 'original'),
        'DR_LifeCycle': getRequestParameter(requestData, 'DR_LifeCycle', []),
        'DR_BKType': getRequestParameter(requestData, 'DR_BKType', 'set'),
        'DR_BKSizePower': int(getRequestParameter(requestData, 'DR_BKSizePower', 2))
    }


def getDataUtilitySettings(requestData):
    return {
        'DU_IsFromSameOrigin': getRequestParameter(requestData, 'DU_IsFromSameOrigin', True),
        'DU_IsAllLifeCycle': getRequestParameter(requestData, 'DU_IsAllLifeCycle', True),
        'DU_EventAttributes': getRequestParameter(requestData, 'DU_EventAttributes', []),
        'DU_TimeAccuracy': getRequestParameter(requestData, 'DU_TimeAccuracy', 'original'),
        'DU_LifeCycle': getRequestParameter(requestData, 'DU_LifeCycle', [])
    }


def getRequestParameter(requestData, parameter, default=None):
    if parameter in requestData:
        if requestData[parameter] is None:
            return default
        else:
            return requestData[parameter]
    else:
        return default


def getUniqueLifecycles(log):
    ret = []
    for tIdx, trace in enumerate(log):
        for eIdx, event in enumerate(trace):
            if 'lifecycle:transition' in event.keys():
                ret.append(event['lifecycle:transition'])
    return list(set(ret))
