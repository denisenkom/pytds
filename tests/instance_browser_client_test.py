import pytds.instance_browser_client


def test_get_instances():
    data = b"\x05[\x00ServerName;MISHA-PC;InstanceName;SQLEXPRESS;IsClustered;No;Version;10.0.1600.22;tcp;49849;;"
    ref = {
        "SQLEXPRESS": {
            "ServerName": "MISHA-PC",
            "InstanceName": "SQLEXPRESS",
            "IsClustered": "No",
            "Version": "10.0.1600.22",
            "tcp": "49849",
        },
    }
    instances = pytds.instance_browser_client.parse_instances_response(data)
    assert instances == ref
