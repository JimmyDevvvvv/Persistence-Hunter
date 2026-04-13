import win32evtlog, win32api

handle = win32evtlog.EvtQuery('Microsoft-Windows-Sysmon/Operational', win32evtlog.EvtQueryReverseDirection, '*[System[(EventID=12 or EventID=13)]]')
events = win32evtlog.EvtNext(ResultSet=handle, Count=2, Timeout=-1, Flags=0)
print('Got', len(events), 'events')
for e in events:
    xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
    print(xml_str)
    print('---')
win32api.CloseHandle(handle)
