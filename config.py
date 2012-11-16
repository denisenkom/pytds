def tds_read_config_info(tds, login, locale):
    return login

#
# Fix configuration after reading it. 
# Currently this read some environment variables and replace some options.
#
def tds_fix_login(login):
    pass
    # Now check the environment variables
    #tds_config_env_tdsver(login)
    #tds_config_env_tdsdump(login)
    #tds_config_env_tdsport(login)
    #tds_config_env_tdshost(login)
