import logging
from tds import *
from mem import *
from threadsafe import *
from sybdb import *
from config import *
from login import *
from query import *

logger = logging.getLogger(__name__)

dblib_mutex = None

_DB_RES_INIT            = 0
_DB_RES_RESULTSET_EMPTY = 1
_DB_RES_RESULTSET_ROWS  = 2
_DB_RES_NEXT_RESULT     = 3
_DB_RES_NO_MORE_RESULTS = 4
_DB_RES_SUCCEED         = 5

REG_ROW         = -1
MORE_ROWS       = -1
NO_MORE_ROWS    = -2
BUF_FULL        = -3
NO_MORE_RESULTS = 2
SUCCEED         = 1
FAIL            = 0

DBSAVE      = 1
DBNOSAVE    = 0
DBNOERR     = -1

INT_EXIT	= 0
INT_CONTINUE	= 1
INT_CANCEL	= 2
INT_TIMEOUT	= 3

EXINFO        =  1
EXUSER        =  2
EXNONFATAL    =  3
EXCONVERSION  =  4
EXSERVER      =  5
EXTIME        =  6
EXPROGRAM     =  7
EXRESOURCE    =  8
EXCOMM        =  9
EXFATAL       = 10
EXCONSISTENCY = 11

SYBEVERDOWN	=   100	# TDS version downgraded . */
SYBEICONVIU	=  2400	# Some character(s) could not be converted into client's character set. */
SYBEICONVAVAIL	=  2401	# Character set conversion is not available between client character set '%.*s' and server character set '%.*s'.*/
SYBEICONVO	=  2402	# Error converting characters into server's character set. Some character(s) could not be converted.*/
SYBEICONVI	=  2403	# Some character(s) could not be converted into client's character set.  Unconverted bytes were changed to question marks ('?').*/
SYBEICONV2BIG	=  2404	# Buffer overflow converting characters from client into server's character set.*/
			# cf. doc/dblib_errors.txt for more iconv error values. */
			# Reserve a few slots for other iconv-related issues. */
SYBETDSVER	=  2410 # Cannot bcp with TDSVER < 5.0 */
SYBEPORT	=  2500	# Both port and instance specified */
SYBESYNC        = 20001	# Read attempted while out of synchronization with SQL Server. */
SYBEFCON        = 20002	# SQL Server connection failed. */
SYBETIME        = 20003	# SQL Server connection timed out. */
SYBEREAD        = 20004	# Read from SQL Server failed. */
SYBEBUFL        = 20005	# DB-LIBRARY internal error - send buffer length corrupted. */
SYBEWRIT        = 20006	# Write to SQL Server failed. */
SYBEVMS         = 20007	# Sendflush: VMS I/O error. */
SYBESOCK        = 20008	# Unable to open socket */
SYBECONN        = 20009	# Unable to connect socket -- SQL Server is unavailable or does not exist. */
SYBEMEM         = 20010	# Unable to allocate sufficient memory */
SYBEDBPS        = 20011	# Maximum number of DBPROCESSes already allocated. */
SYBEINTF        = 20012	# Server name not found in interface file */
SYBEUHST        = 20013	# Unknown host machine name */
SYBEPWD         = 20014	# Incorrect password. */
SYBEOPIN        = 20015	# Could not open interface file. */
SYBEINLN        = 20016	# Interface file: unexpected end-of-line. */
SYBESEOF        = 20017	# Unexpected EOF from SQL Server. */
SYBESMSG        = 20018	# General SQL Server error: Check messages from the SQL Server. */
SYBERPND        = 20019	# Attempt to initiate a new SQL Server operation with results pending. */
SYBEBTOK        = 20020	# Bad token from SQL Server: Data-stream processing out of sync. */
SYBEITIM        = 20021	# Illegal timeout value specified. */
SYBEOOB         = 20022	# Error in sending out-of-band data to SQL Server. */
SYBEBTYP        = 20023	# Unknown bind type passed to DB-LIBRARY function. */
SYBEBNCR        = 20024	# Attempt to bind user variable to a non-existent compute row. */
SYBEIICL        = 20025	# Illegal integer column length returned by SQL Server. Legal integer lengths are 1, 2, and 4 bytes. */
SYBECNOR        = 20026	# Column number out of range. */
SYBENPRM        = 20027	# NULL parameter not allowed for this dboption. */
SYBEUVDT        = 20028	# Unknown variable-length datatype encountered. */
SYBEUFDT        = 20029	# Unknown fixed-length datatype encountered. */
SYBEWAID        = 20030	# DB-LIBRARY internal error: ALTFMT following ALTNAME has wrong id. */
SYBECDNS        = 20031	# Datastream indicates that a compute column is derived from a non-existent select-list member. */
SYBEABNC        = 20032	# Attempt to bind to a non-existent column. */
SYBEABMT        = 20033	# User attempted a dbbind() with mismatched column and variable types. */
SYBEABNP        = 20034	# Attempt to bind using NULL pointers. */
SYBEAAMT        = 20035	# User attempted a dbaltbind() with mismatched column and variable types. */
SYBENXID        = 20036	# The Server did not grant us a distributed-transaction ID. */
SYBERXID        = 20037	# The Server did not recognize our distributed-transaction ID. */
SYBEICN         = 20038	# Invalid computeid or compute column number. */
SYBENMOB        = 20039	# No such member of 'order by' clause. */
SYBEAPUT        = 20040	# Attempt to print unknown token. */
SYBEASNL        = 20041	# Attempt to set fields in a null loginrec. */
SYBENTLL        = 20042	# Name too long for loginrec field. */
SYBEASUL        = 20043	# Attempt to set unknown loginrec field. */
SYBERDNR        = 20044	# Attempt to retrieve data from a non-existent row. */
SYBENSIP        = 20045	# Negative starting index passed to dbstrcpy(). */
SYBEABNV        = 20046	# Attempt to bind to a NULL program variable. */
SYBEDDNE        = 20047	# DBPROCESS is dead or not enabled. */
SYBECUFL        = 20048	# Data-conversion resulted in underflow. */
SYBECOFL        = 20049	# Data-conversion resulted in overflow. */
SYBECSYN        = 20050	# Attempt to convert data stopped by syntax error in source field. */
SYBECLPR        = 20051	# Data-conversion resulted in loss of precision. */
SYBECNOV        = 20052	# Attempt to set variable to NULL resulted in overflow. */
SYBERDCN        = 20053	# Requested data-conversion does not exist. */
SYBESFOV        = 20054	# dbsafestr() overflowed its destination buffer. */
SYBEUNT         = 20055	# Unknown network type found in interface file. */
SYBECLOS        = 20056	# Error in closing network connection. */
SYBEUAVE        = 20057	# Unable to allocate VMS event flag. */
SYBEUSCT        = 20058	# Unable to set communications timer. */
SYBEEQVA        = 20059	# Error in queueing VMS AST routine. */
SYBEUDTY        = 20060	# Unknown datatype encountered. */
SYBETSIT        = 20061	# Attempt to call dbtsput() with an invalid timestamp. */
SYBEAUTN        = 20062	# Attempt to update the timestamp of a table which has no timestamp column. */
SYBEBDIO        = 20063	# Bad bulk-copy direction.  Must be either IN or OUT. */
SYBEBCNT        = 20064	# Attempt to use Bulk Copy with a non-existent Server table. */
SYBEIFNB        = 20065	# Illegal field number passed to bcp_control(). */
SYBETTS         = 20066	# The table which bulk-copy is attempting to copy to a host-file is shorter than the number of rows which bulk-copy was instructed to skip. */
SYBEKBCO        = 20067	# 1000 rows successfully bulk-copied to host-file. */
SYBEBBCI        = 20068	# Batch successfully bulk-copied to SQL Server. */
SYBEKBCI        = 20069	# Bcp: 1000 rows sent to SQL Server. */
SYBEBCRE        = 20070	# I/O error while reading bcp data-file. */
SYBETPTN        = 20071	# Syntax error: only two periods are permitted in table names. */
SYBEBCWE        = 20072	# I/O error while writing bcp data-file. */
SYBEBCNN        = 20073	# Attempt to bulk-copy a NULL value into Server column %d,  which does not accept NULL values. */
SYBEBCOR        = 20074	# Attempt to bulk-copy an oversized row to the SQL Server. */
SYBEBCIS        = 20075	# Attempt to bulk-copy an illegally-sized column value to the SQL Server. */
SYBEBCPI        = 20076	# bcp_init() must be called before any other bcp routines. */
SYBEBCPN        = 20077	# bcp_bind(), bcp_collen(), bcp_colptr(), bcp_moretext() and bcp_sendrow() may be used only after bcp_init() has been called with the copy direction set to DB_IN. */
SYBEBCPB        = 20078	# bcp_bind(), bcp_moretext() and bcp_sendrow() may NOT be used after bcp_init() has been passed a non-NULL input file name. */
SYBEVDPT        = 20079	# For bulk copy, all variable-length data must have either a length-prefix or a terminator specified. */
SYBEBIVI        = 20080	# bcp_columns(), bcp_colfmt() and bcp_colfmt_ps() may be used only after bcp_init() has been passed a valid input file. */
SYBEBCBC        = 20081	# bcp_columns() must be called before bcp_colfmt() and bcp_colfmt_ps(). */
SYBEBCFO        = 20082	# Bcp host-files must contain at least one column. */
SYBEBCVH        = 20083	# bcp_exec() may be called only after bcp_init() has been passed a valid host file. */
SYBEBCUO        = 20084	# Bcp: Unable to open host data-file. */
SYBEBCUC        = 20085	# Bcp: Unable to close host data-file. */
SYBEBUOE        = 20086	# Bcp: Unable to open error-file. */
SYBEBUCE        = 20087	# Bcp: Unable to close error-file. */
SYBEBWEF        = 20088	# I/O error while writing bcp error-file. */
SYBEASTF        = 20089	# VMS: Unable to setmode for control_c ast. */
SYBEUACS        = 20090	# VMS: Unable to assign channel to sys$command. */
SYBEASEC        = 20091	# Attempt to send an empty command buffer to the SQL Server. */
SYBETMTD        = 20092	# Attempt to send too much TEXT data via the dbmoretext() call. */
SYBENTTN        = 20093	# Attempt to use dbtxtsput() to put a new text-timestamp into a non-existent data row. */
SYBEDNTI        = 20094	# Attempt to use dbtxtsput() to put a new text-timestamp into a column whose datatype is neither SYBTEXT nor SYBIMAGE. */
SYBEBTMT        = 20095	# Attempt to send too much TEXT data via the bcp_moretext() call. */
SYBEORPF        = 20096	# Attempt to set remote password would overflow the login-record's remote-password field. */
SYBEUVBF        = 20097	# Attempt to read an unknown version of BCP format-file. */
SYBEBUOF        = 20098	# Bcp: Unable to open format-file. */
SYBEBUCF        = 20099	# Bcp: Unable to close format-file. */
SYBEBRFF        = 20100	# I/O error while reading bcp format-file. */
SYBEBWFF        = 20101	# I/O error while writing bcp format-file. */
SYBEBUDF        = 20102	# Bcp: Unrecognized datatype found in format-file. */
SYBEBIHC        = 20103	# Incorrect host-column number found in bcp format-file. */
SYBEBEOF        = 20104	# Unexpected EOF encountered in BCP data-file. */
SYBEBCNL        = 20105	# Negative length-prefix found in BCP data-file. */
SYBEBCSI        = 20106	# Host-file columns may be skipped only when copying INto the Server. */
SYBEBCIT        = 20107	# It's illegal to use BCP terminators with program variables other than SYBCHAR, SYBBINARY, SYBTEXT, or SYBIMAGE. */
SYBEBCSA        = 20108	# The BCP hostfile '%s' contains only %ld rows. Skipping all of these rows is not allowed. */
SYBENULL        = 20109	# NULL DBPROCESS pointer passed to DB-Library. */
SYBEUNAM        = 20110	# Unable to get current username from operating system. */
SYBEBCRO        = 20111	# The BCP hostfile '%s' contains only %ld rows. It was impossible to read the requested %ld rows. */
SYBEMPLL        = 20112	# Attempt to set maximum number of DBPROCESSes lower than 1. */
SYBERPIL        = 20113	# It is illegal to pass -1 to dbrpcparam() for the datalen of parameters which are of type SYBCHAR, SYBVARCHAR, SYBBINARY, or SYBVARBINARY. */
SYBERPUL        = 20114	# When passing a SYBINTN, SYBDATETIMN, SYBMONEYN, or SYBFLTN parameter via dbrpcparam(), it's necessary to specify the parameter's maximum or actual length, so that DB-Library can recognize it as a SYBINT1, SYBINT2, SYBINT4, SYBMONEY, or SYBMONEY4, etc. */
SYBEUNOP        = 20115	# Unknown option passed to dbsetopt(). */
SYBECRNC        = 20116	# The current row is not a result of compute clause %d, so it is illegal to attempt to extract that data from this row. */
SYBERTCC        = 20117	# dbreadtext() may not be used to receive the results of a query which contains a COMPUTE clause. */
SYBERTSC        = 20118	# dbreadtext() may only be used to receive the results of a query which contains a single result column. */
SYBEUCRR        = 20119	# Internal software error: Unknown connection result reported by                                                 * dbpasswd(). */
SYBERPNA        = 20120	# The RPC facility is available only when using a SQL Server whose version number is 4.0 or greater. */
SYBEOPNA        = 20121	# The text/image facility is available only when using a SQL Server whose version number is 4.0 or greater. */
SYBEFGTL        = 20122	# Bcp: Row number of the first row to be copied cannot be greater than the row number for the last row to be copied.  */
SYBECWLL        = 20123	# Attempt to set column width less than 1.  */
SYBEUFDS        = 20124	# Unrecognized format encountered in dbstrbuild(). */
SYBEUCPT        = 20125	# Unrecognized custom-format parameter-type encountered in dbstrbuild(). */
SYBETMCF        = 20126	# Attempt to install too many custom formats via dbfmtinstall(). */
SYBEAICF        = 20127	# Error in attempting to install custom format. */
SYBEADST        = 20128	# Error in attempting to determine the size of a pair of translation tables. */
SYBEALTT        = 20129	# Error in attempting to load a pair of translation tables. */
SYBEAPCT        = 20130	# Error in attempting to perform a character-set translation. */
SYBEXOCI        = 20131	# A character-set translation overflowed its destination buffer while using bcp to copy data from a host-file to the SQL Server. */
SYBEFSHD        = 20132	# Error in attempting to find the Sybase home directory. */
SYBEAOLF        = 20133	# Error in attempting to open a localization file. */
SYBEARDI        = 20134	# Error in attempting to read datetime information from a localization file. */
SYBEURCI        = 20135	# Unable to read copyright information from the dblib localization file. */
SYBEARDL        = 20136	# Error in attempting to read the dblib.loc localization file. */
SYBEURMI        = 20137	# Unable to read money-format information from the dblib localization file. */
SYBEUREM        = 20138	# Unable to read error mnemonic from the dblib localization file. */
SYBEURES        = 20139	# Unable to read error string from the dblib localization file. */
SYBEUREI        = 20140	# Unable to read error information from the dblib localization file. */
SYBEOREN        = 20141	# Warning: an out-of-range error-number was encountered in dblib.loc. The maximum permissible error-number is defined as DBERRCOUNT in sybdb.h. */
SYBEISOI        = 20142	# Invalid sort-order information found. */
SYBEIDCL        = 20143	# Illegal datetime column length returned by DataServer. Legal datetime lengths are 4 and 8 bytes. */
SYBEIMCL        = 20144	# Illegal money column length returned by DataServer. Legal money lengths are 4 and 8 bytes. */
SYBEIFCL        = 20145	# Illegal floating-point column length returned by DataServer. Legal floating-point lengths are 4 and 8 bytes. */
SYBEUTDS        = 20146	# Unrecognized TDS version received from SQL Server. */
SYBEBUFF        = 20147	# Bcp: Unable to create format-file. */
SYBEACNV        = 20148	# Attemp to do conversion with NULL destination variable. */
SYBEDPOR        = 20149	# Out-of-range datepart constant. */
SYBENDC         = 20150	# Cannot have negative component in date in numeric form. */
SYBEMVOR        = 20151	# Month values must be between 1 and 12. */
SYBEDVOR        = 20152	# Day values must be between 1 and 7. */
SYBENBVP        = 20153	# Cannot pass dbsetnull() a NULL bindval pointer. */
SYBESPID        = 20154	# Called dbspid() with a NULL dbproc. */
SYBENDTP        = 20155	# Called dbdatecrack() with a NULL datetime  parameter. */
SYBEXTN         = 20156	# The xlt_todisp and xlt_tosrv parameters to dbfree_xlate() were NULL. */
SYBEXTDN        = 20157	# Warning:  the xlt_todisp parameter to dbfree_xlate() was NULL.  The space associated with the xlt_tosrv parameter has been freed. */
SYBEXTSN        = 20158	# Warning:  the xlt_tosrv parameter to dbfree_xlate() was NULL.  The space associated with the xlt_todisp parameter has been freed. */
SYBENUM         = 20159	# Incorrect number of arguments given  to DB-Library.  */
SYBETYPE        = 20160	# Invalid argument type given to DB-Library. */
SYBEGENOS       = 20161	# General Operating System Error. */
SYBEPAGE        = 20162	# wrong resource type or length given for  dbpage() operation.  */
SYBEOPTNO       = 20163	# Option is not allowed or is unreconized */
SYBEETD         = 20164	# Failure to send the expected amount of  TEXT or IMAGE data via dbmoretext(). */
SYBERTYPE       = 20165	# Invalid resource type given to DB-Library. */
SYBERFILE       = 20166	# "Can not open resource file." */
SYBEFMODE       = 20167	# Read/Write/Append mode denied on file. */
SYBESLCT        = 20168	# Could not select or copy field specified */
SYBEZTXT        = 20169	# Attempt to send zero length TEXT or  IMAGE to dataserver via dbwritetext(). */
SYBENTST        = 20170	# The file being opened must be a stream_lf. */
SYBEOSSL        = 20171	# Operating system login level not in range of Secure SQL Server */
SYBEESSL        = 20172	# Login security level entered does not agree with operating system level */
SYBENLNL        = 20173	# Program not linked with specified network library. */
SYBENHAN        = 20174	# called dbrecvpassthru() with a NULL handler parameter. */
SYBENBUF        = 20175	# called dbsendpassthru() with a NULL buf pointer. */
SYBENULP        = 20176	# Called %s with a NULL %s parameter. */
SYBENOTI        = 20177	# No event handler installed. */
SYBEEVOP        = 20178	# Called dbregwatch() with a bad options parameter. */
SYBENEHA        = 20179	# Called dbreghandle() with a NULL handler parameter. */
SYBETRAN        = 20180	# DBPROCESS is being used for another transaction. */
SYBEEVST        = 20181	# Must initiate a transaction before calling dbregparam(). */
SYBEEINI        = 20182	# Must call dbreginit() before dbregraise(). */
SYBEECRT        = 20183	# Must call dbregdefine() before dbregcreate(). */
SYBEECAN        = 20184	# Attempted to cancel unrequested event notification. */
SYBEEUNR        = 20185	# Unsolicited event notification received. */
SYBERPCS        = 20186	# Must call dbrpcinit() before dbrpcparam(). */
SYBETPAR        = 20187	# No SYBTEXT or SYBIMAGE parameters were defined. */
SYBETEXS        = 20188	# Called dbmoretext() with a bad size parameter. */
SYBETRAC        = 20189	# Attempted to turn off a trace flag that was not on. */
SYBETRAS        = 20190	# DB-Library internal error - trace structure not found. */
SYBEPRTF        = 20191	# dbtracestring() may only be called from a printfunc(). */
SYBETRSN        = 20192	# Bad numbytes parameter passed to dbtracestring(). */
SYBEBPKS        = 20193	# In DBSETLPACKET(), the packet size parameter must be between 0 and 999999. */
SYBEIPV         = 20194	# %1! is an illegal value for the %2! parameter of %3!. */
SYBEMOV         = 20195	# Money arithmetic resulted in overflow in function %1!. */
SYBEDIVZ        = 20196	# Attempt to divide by $0.00 in function %1!. */
SYBEASTL        = 20197	# Synchronous I/O attempted at AST level. */
SYBESEFA        = 20198	# DBSETNOTIFS cannot be called if connections are present. */
SYBEPOLL        = 20199	# Only one dbpoll() can be active at a time. */
SYBENOEV        = 20200	# dbpoll() cannot be called if registered procedure notifications have been disabled. */
SYBEBADPK       = 20201	# Packet size of %1! not supported. -- size of %2! used instead. */
SYBESECURE      = 20202	# Secure Server function not supported in this version. */
SYBECAP         = 20203	# DB-Library capabilities not accepted by the Server. */
SYBEFUNC        = 20204	# Functionality not supported at the specified version level. */
SYBERESP        = 20205	# Response function address passed to dbresponse() must be non-NULL. */
SYBEIVERS       = 20206	# Illegal version level specified. */
SYBEONCE        = 20207	# Function can be called only once. */
SYBERPNULL      = 20208	# value parameter for dbprcparam() can be NULL, only if the datalen parameter is 0 */
SYBERPTXTIM     = 20209	# RPC parameters cannot be of type Text/Image. */
SYBENEG         = 20210	# Negotiated login attempt failed. */
SYBELBLEN       = 20211	# Security labels should be less than 256 characters long. */
SYBEUMSG        = 20212	# Unknown message-id in MSG datastream. */
SYBECAPTYP      = 20213	# Unexpected capability type in CAPABILITY datastream. */
SYBEBNUM        = 20214	# Bad numbytes parameter passed to dbstrcpy() */
SYBEBBL         = 20215	# Bad bindlen parameter passed to dbsetnull() */
SYBEBPREC       = 20216	# Illegal precision specified */
SYBEBSCALE      = 20217	# Illegal scale specified */
SYBECDOMAIN     = 20218	# Source field value is not within the domain of legal values. */
SYBECINTERNAL   = 20219	# Internal Conversion error. */
SYBEBTYPSRV     = 20220	# Datatype is not supported by the server. */
SYBEBCSET       = 20221	# Unknown character-set encountered." */
SYBEFENC        = 20222	# Password Encryption failed." */
SYBEFRES        = 20223	# Challenge-Response function failed.", */
SYBEISRVPREC    = 20224	# Illegal precision value returned by the server. */
SYBEISRVSCL     = 20225	# Illegal scale value returned by the server. */
SYBEINUMCL      = 20226	# Invalid numeric column length returned by the server. */
SYBEIDECCL      = 20227	# Invalid decimal column length returned by the server. */
SYBEBCMTXT      = 20228	# bcp_moretext() may be used only when there is at least one text or image column in the server table. */
SYBEBCPREC      = 20229	# Column %1!: Illegal precision value encountered. */
SYBEBCBNPR      = 20230	# bcp_bind(): if varaddr is NULL, prefixlen must be 0 and no terminator should be specified. */
SYBEBCBNTYP     = 20231	# bcp_bind(): if varaddr is NULL and varlen greater than 0, the table column type must be SYBTEXT or SYBIMAGE and the program variable type must be SYBTEXT, SYBCHAR, SYBIMAGE or SYBBINARY. */
SYBEBCSNTYP     = 20232	# column number %1!: if varaddr is NULL and varlen greater than 0, the table column type must be SYBTEXT or SYBIMAGE and the program variable type must be SYBTEXT, SYBCHAR, SYBIMAGE or SYBBINARY. */
SYBEBCPCTYP     = 20233	# bcp_colfmt(): If table_colnum is 0, host_type cannot be 0. */
SYBEBCVLEN      = 20234	# varlen should be greater than or equal to -1. */
SYBEBCHLEN      = 20235	# host_collen should be greater than or equal to -1. */
SYBEBCBPREF     = 20236	# Illegal prefix length. Legal values are 0, 1, 2 or 4. */
SYBEBCPREF      = 20237	# Illegal prefix length. Legal values are -1, 0, 1, 2 or 4. */
SYBEBCITBNM     = 20238	# bcp_init(): tblname parameter cannot be NULL. */
SYBEBCITBLEN    = 20239	# bcp_init(): tblname parameter is too long. */
SYBEBCSNDROW    = 20240	# bcp_sendrow() may NOT be called unless all text data for the previous row has been sent using bcp_moretext(). */
SYBEBPROCOL     = 20241	# bcp protocol error: returned column count differs from the actual number of columns received. */
SYBEBPRODEF     = 20242	# bcp protocol error: expected default information and got none. */
SYBEBPRONUMDEF  = 20243	# bcp protocol error: expected number of defaults differs from the actual number of defaults received. */
SYBEBPRODEFID   = 20244	# bcp protocol error: default column id and actual column id are not same */
SYBEBPRONODEF   = 20245	# bcp protocol error:  default value received for column that does not have default. */
SYBEBPRODEFTYP  = 20246	# bcp protocol error:  default value datatype differs from column datatype. */
SYBEBPROEXTDEF  = 20247	# bcp protocol error: more than one row of default information received. */
SYBEBPROEXTRES  = 20248	# bcp protocol error: unexpected set of results received. */
SYBEBPROBADDEF  = 20249	# bcp protocol error: illegal default column id received. */
SYBEBPROBADTYP  = 20250	# bcp protocol error: unknown column datatype. */
SYBEBPROBADLEN  = 20251	# bcp protocol error: illegal datatype length received. */
SYBEBPROBADPREC = 20252	# bcp protocol error: illegal precision value received. */
SYBEBPROBADSCL  = 20253	# bcp protocol error: illegal scale value received. */
SYBEBADTYPE     = 20254	# Illegal value for type parameter  given to %1!. */
SYBECRSNORES    = 20255	# Cursor statement generated no results. */
SYBECRSNOIND    = 20256	# One of the tables involved in the cursor  statement does not have a unique index. */
SYBECRSVIEW     = 20257	# A view cannot be joined with another table  or a view in a cursor statement. */
SYBECRSVIIND    = 20258	# The view used in the cursor statement does  not include all the unique index columns of  the underlying tables. */
SYBECRSORD      = 20259	# Only fully keyset driven cursors can have 'order by', ' group by', or 'having' phrases. */
SYBECRSBUFR     = 20260	# Row buffering should not be turned on when  using cursor APIs. */
SYBECRSNOFREE   = 20261	# The DBNOAUTOFREE option should not be  turned on when using cursor APIs. */
SYBECRSDIS      = 20262	# Cursor statement contains one of the  disallowed phrases 'compute', 'union', 'for browse', or 'select into'. */
SYBECRSAGR      = 20263	# Aggregate functions are not allowed in a  cursor statement. */
SYBECRSFRAND    = 20264	# Fetch types RANDOM and RELATIVE can only be  used within the keyset of keyset driven  cursors. */
SYBECRSFLAST    = 20265	# Fetch type LAST requires fully keyset  driven cursors. */
SYBECRSBROL     = 20266	# Backward scrolling cannot be used in a  forward scrolling cursor. */
SYBECRSFROWN    = 20267	# Row number to be fetched is outside valid  range. */
SYBECRSBSKEY    = 20268	# Keyset cannot be scrolled backward in mixed  cursors with a previous fetch type. */
SYBECRSRO       = 20269	# Data locking or modifications cannot be  made in a READONLY cursor. */
SYBECRSNOCOUNT  = 20270	# The DBNOCOUNT option should not be  turned on when doing updates or deletes with  dbcursor(). */
SYBECRSTAB      = 20271	# Table name must be determined in operations  involving data locking or modifications. */
SYBECRSUPDNB    = 20272	# Update or insert operations cannot use bind  variables when binding type is NOBIND. */
SYBECRSNOWHERE  = 20273	# A WHERE clause is not allowed in a cursor  update or insert. */
SYBECRSSET      = 20274	# A SET clause is required for a cursor  update or insert.  */
SYBECRSUPDTAB   = 20275	# Update or insert operations using bind  variables require single table cursors. */
SYBECRSNOUPD    = 20276	# Update or delete operation did not affect  any rows. */
SYBECRSINV      = 20277	# Invalid cursor statement. */
SYBECRSNOKEYS   = 20278	# The entire keyset must be defined for KEYSET cursors. */
SYBECRSNOBIND   = 20279	# Cursor bind must be called prior to updating cursor */
SYBECRSFTYPE    = 20280	# Unknown fetch type. */
SYBECRSINVALID  = 20281	# The cursor handle is invalid. */
SYBECRSMROWS    = 20282	# Multiple rows are returned, only one is expected. */
SYBECRSNROWS    = 20283	# No rows returned, at least one is expected. */
SYBECRSNOLEN    = 20284	# No unique index found. */
SYBECRSNOPTCC   = 20285	# No OPTCC was found. */
SYBECRSNORDER   = 20286	# The order of clauses must be from, where, and order by. */
SYBECRSNOTABLE  = 20287	# Table name is NULL. */
SYBECRSNUNIQUE  = 20288	# No unique keys associated with this view. */
SYBECRSVAR      = 20289	# There is no valid address associated with this bind. */
SYBENOVALUE     = 20290	# Security labels require both a name and a value */
SYBEVOIDRET     = 20291	# Parameter of type SYBVOID cannot  be a return parameter. */
SYBECLOSEIN     = 20292	# Unable to close interface file. */
SYBEBOOL        = 20293	# Boolean parameters must be TRUE or FALSE. */
SYBEBCPOPT      = 20294	# The  option cannot be called while a bulk copy operation is progress. */
SYBEERRLABEL    = 20295	# An illegal value was returned from the security label handler. */
SYBEATTNACK     = 20296	# Timed out waiting for server to acknowledge attention." */
SYBEBBFL        = 20297	# -001- Batch failed in bulk-copy to SQL Server */
SYBEDCL         = 20298	# -004- DCL Error */
SYBECS          = 20299	# -004- cs context Error */
SYBEBULKINSERT  = 20599	# cannot build bulk insert statement */

def CHECK_CONN(conn):
    pass

#
# Return the current row buffer index.  
# We strive to validate it first.  It must be:
# 	between zero and capacity (obviously), and
# 	between the head and the tail, logically.  
#
# If the head has wrapped the tail, it shouldn't be in no man's land.  
# IOW, if capacity is 9, head is 3 and tail is 7, good rows are 7-8 and 0-2.
#      (Row 3 is about-to-be-inserted, and 4-6 are not in use.)  Here's a diagram:
# 		d d d ! ! ! ! d d
#		0 1 2 3 4 5 6 7 8
#		      ^       ^
#		      Head    Tail
#
# The special case is capacity == 1, meaning there's no buffering, and head == tail === 0.  
#
def buffer_current_index(dbproc):
    buf = dbproc.row_buf
    if buf.capacity <= 1: # no buffering
        return -1
    raise Exception('not implemented')
    #if (buf->current == buf->head || buf->current == buf->capacity)
    #        return -1;
    #        
    #assert(buf->current >= 0);
    #assert(buf->current < buf->capacity);
    #
    #if( buf->tail < buf->head) {
    #        assert(buf->tail < buf->current);
    #        assert(buf->current < buf->head);
    #} else {
    #        if (buf->current > buf->head)
    #                assert(buf->current > buf->tail);
    #}
    #return buf->current;

def buffer_set_capacity(dbproc, nrows):
    buf = dbproc.row_buf
    if nrows == 0:
        buf.capacity = 1
        return
    buf.capacity = nrows

def buffer_count(buf):
    return buf.capacity

def buffer_is_full(buf):
    #BUFFER_CHECK(buf)
    return buf.capacity == buffer_count(buf) and buf.capacity > 1

def buffer_free(dbproc):
    pass

def buffer_alloc(dbproc):
    pass

def buffer_save_row(dbproc):
    buf = dbproc.row_buf
    if buf.capacity <= 1:
        return SUCCEED
    raise Exception('not implemented')

def buffer_row_address(buf, idx):
    #BUFFER_CHECK(buf)
    if idx < 0 or idx >= buf.capacity:
        #printf("idx is %d:\n", idx);
        #buffer_struct_print(buf);
        return None
    return buf.rows[idx]

def buffer_add_row(dbproc, resinfo):
    buf = dbproc.row_buf
    assert buf.capacity >= 0

    if buffer_is_full(buf):
        return -1

    row = buffer_row_address(buf, buf.head)

    # bump the row number, write it, and move the data to head
    if row.resinfo:
        tds_free_row(row.resinfo, row.row_data)
        tds_free_results(row.resinfo)
    buf.received += 1
    row.row = buf.received
    resinfo.ref_count += 1
    row.resinfo = resinfo
    row.row_data = None
    row.sizes = []
    for col in resinfo.columns:
        row.sizes.append(col.column_cur_size)

    # initial condition is head == 0 and tail == capacity
    if buf.tail == buf.capacity:
        # bumping this tail will set it to zero
        assert buf.head == 0
        buf.tail = 0

    # update current, bump the head
    buf.current = buf.head
    buf.head = buffer_idx_increment(buf, buf.head)

    return buf.current

def buffer_idx_increment(buf, idx):
    idx += 1
    if idx >= buf.capacity:
        idx = 0
    return idx

def buffer_transfer_bound_data(buf, res_type, compute_id, dbproc, idx):
    logger.debug("buffer_transfer_bound_data(%d %d %d)", res_type, compute_id, idx)
    #BUFFER_CHECK(buf);
    #assert buffer_index_valid(buf, idx)

    row = buffer_row_address(buf, idx)
    assert row.resinfo

    for i, curcol in enumerate(row.resinfo.columns):
        if row.sizes:
            curcol.column_cur_size = row.sizes[i]

        if curcol.column_nullbind:
            if curcol.column_cur_size < 0:
                curcol.column_nullbind = -1
            else:
                curcol.column_nullbind = 0
        if not curcol.column_varaddr:
            continue

        if row.row_data:
            src = row.row_data[curcol.column_data - row.resinfo.current_row]
        else:
            src = curcol.column_data
        srclen = curcol.column_cur_size;
        if is_blob_col(curcol):
            src = src.textvalue
        desttype = dblib_bound_type(curcol.column_bindtype)
        srctype = tds_get_conversion_type(curcol.column_type, curcol.column_size)

        if srclen <= 0:
            if srclen == 0 or not curcol.column_nullbind:
                dbgetnull(dbproc, curcol.column_bindtype, curcol.column_bindlen,
                                curcol.column_varaddr)
        else:
            copy_data_to_host_var(dbproc, srctype, src, srclen, desttype, 
                                    curcol.column_varaddr,  curcol.column_bindlen,
                                                curcol.column_bindtype, curcol.column_nullbind)

    #
    # this function always bumps current.  usually, it's called 
    # by dbnextrow(), so bumping current is a pretty obvious choice.  
    # it can also be called by dbgetrow(), but that function also 
    # causes the bump.  if you call dbgetrow() for row n, a subsequent
    # call to dbnextrow() yields n+1.
    #
    buf.current = buffer_idx_increment(buf, buf.current)

def dblib_add_connection(ctx, tds):
    ctx.connection_list.append(tds)

def dblib_del_connection(ctx, tds):
    ctx.connection_list.remove(tds)

def dblib_release_tds_ctx(count):
    logger.debug("dblib_release_tds_ctx(%d)", count)
    pass

# \internal
# \ingroup dblib_internal
# \brief Sanity checks for column-oriented functions.  
# 
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \param pcolinfo address of pointer to a TDSCOLUMN structure.
# \remarks Makes sure dbproc and the requested column are valid.  
#       Calls dbperror() if not.  
# \returns appropriate error or SUCCEED
#
def dbcolptr(dbproc, column):
    if not dbproc:
        dbperror(dbproc, SYBENULL, 0)
        return None
    if IS_TDSDEAD(dbproc.tds_socket):
        dbperror(dbproc, SYBEDDNE, 0)
        return None
    if not dbproc.tds_socket.res_info:
        return None
    if column < 1 or column > len(dbproc.tds_socket.res_info.columns):
        dbperror(dbproc, SYBECNOR, 0)
        return None
    return dbproc.tds_socket.res_info.columns[column - 1]

def dbdata(dbproc, column):
    colinfo = dbcolptr(dbproc, column)
    if colinfo.column_cur_size < 0:
        return None
    if is_blob_col(colinfo):
        return colinfo.column_data.textvalue
    else:
        return colinfo.column_data

#
# \ingroup dblib_core
# \brief Get the datatype of a regular result set column. 
#
#
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \param column Nth in the result set, starting from 1.
# \returns \c SYB* datetype token value, or zero if \a column out of range
# \sa dbcollen(), dbcolname(), dbdata(), dbdatlen(), dbnumcols(), dbprtype(), dbvarylen().
#
def dbcoltype(dbproc, column):
    logger.debug("dbcoltype(%d)" % column)
    #CHECK_PARAMETER(dbproc, SYBENULL, 0)

    colinfo = dbcolptr(dbproc, column)
    if not colinfo:
            return -1

    if colinfo.column_type == SYBVARCHAR:
        return SYBCHAR
    elif colinfo.column_type == SYBVARBINARY:
        return SYBBINARY
    #return tds_get_conversion_type(colinfo.column_type, colinfo.column_size)
    return colinfo.column_type

#
# \ingroup dblib_core
# \brief   Get size of current row's data in a regular result column.  
#
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \param column Nth in the result set, starting from 1.
# \return size of the data, in bytes.
# \sa dbcollen(), dbcolname(), dbcoltype(), dbdata(), dbnumcols().
#
def dbdatlen(dbproc, column):
    logger.debug("dbdatlen(%d)", column)
    #CHECK_PARAMETER(dbproc, SYBENULL, -1)

    colinfo = dbcolptr(dbproc, column)
    if not colinfo:
        return -1

    size = 0 if colinfo.column_cur_size < 0 else colinfo.column_cur_size

    logger.debug("dbdatlen() type = %d, len= %d", colinfo.column_type, size)

    return size

def dbnextrow(dbproc):
    result = FAIL
    logger.debug("dbnextrow()")
    tds = dbproc.tds_socket
    resinfo = tds.res_info
    if not resinfo or dbproc.dbresults_state != _DB_RES_RESULTSET_ROWS:
        # no result set or result set empty (no rows)
        logger.debug("leaving dbnextrow() returning %d (NO_MORE_ROWS)", NO_MORE_ROWS)
        dbproc.row_type = NO_MORE_ROWS
        return NO_MORE_ROWS

    #
    # Try to get the dbproc->row_buf.current item from the buffered rows, if any.  
    # Else read from the stream, unless the buffer is exhausted.  
    # If no rows are read, DBROWTYPE() will report NO_MORE_ROWS. 
    #/
    dbproc.row_type = NO_MORE_ROWS
    computeid = REG_ROW;
    idx = buffer_current_index(dbproc)
    if -1 != idx:
        #
        # Cool, the item we want is already there
        #
        result = dbproc.row_type = REG_ROW
        res_type = TDS_ROW_RESULT
    elif buffer_is_full(dbproc.row_buf):
        result = BUF_FULL
        res_type = TDS_ROWFMT_RESULT
    else:
        pivot = dbrows_pivoted(dbproc)
        if pivot:
            logger.debug("returning pivoted row")
            return dbnextrow_pivoted(dbproc, pivot)
        else:
            mask = TDS_STOPAT_ROWFMT|TDS_RETURN_DONE|TDS_RETURN_ROW|TDS_RETURN_COMPUTE
            buffer_save_row(dbproc)

            # Get the row from the TDS stream.
            rc, res_type, _ = tds_process_tokens(tds, mask)
            if rc == TDS_SUCCESS:
                if res_type in (TDS_ROW_RESULT, TDS_COMPUTE_RESULT):
                    if res_type == TDS_COMPUTE_RESULT:
                        computeid = tds.current_results.computeid
                    # Add the row to the row buffer, whose capacity is always at least 1
                    resinfo = tds.current_results
                    idx = buffer_add_row(dbproc, resinfo)
                    assert idx != -1
                    result = dbproc.row_type = REG_ROW if res_type == TDS_ROW_RESULT else computeid
                    if False:
                        _, res_type, _ = tds_process_tokens(tds, TDS_TOKEN_TRAILING)
                else:
                    dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                    result = NO_MORE_ROWS
            elif rc == TDS_NO_MORE_RESULTS:
                dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                result = NO_MORE_ROWS
            else:
                logger.debug("unexpected: leaving dbnextrow() returning FAIL")
                return FAIL

    if res_type in (TDS_ROW_RESULT, TDS_COMPUTE_RESULT):
        #
        # Transfer the data from the row buffer to the bound variables.
        #
        buffer_transfer_bound_data(dbproc.row_buf, res_type, computeid, dbproc, idx)

    if res_type == TDS_COMPUTE_RESULT:
        logger.debug("leaving dbnextrow() returning compute_id %d\n", result)
    else:
        logger.debug("leaving dbnextrow() returning %s\n", prdbretcode(result))
    return result

# \internal
# \ingroup dblib_internal
# \remarks member msgno Vendor-defined message number
# \remarks member severity Is passed to the error handler 
# \remarks member msgtext Text of message
#
class _dblib_error_message:
    def __init__(self, msgno, severity, msgtext):
        self.msgno = msgno
        self.severity = severity
        self.msgtext = msgtext
DBLIB_ERROR_MESSAGE = _dblib_error_message

#/**  \internal
# * \ingroup dblib_internal
# * \brief Call client-installed error handler
# * 
# * \param dbproc contains all information needed by db-lib to manage communications with the server.
# * \param msgno        identifies the error message to be passed to the client's handler.
# * \param errnum identifies the OS error (errno), if any.  Use 0 if not applicable.  
# * \returns the handler's return code, subject to correction and adjustment for vendor style:
# *     - INT_CANCEL    The db-lib function that encountered the error will return FAIL.  
# *     - INT_TIMEOUT   The db-lib function will cancel the operation and return FAIL.  \a dbproc remains useable.  
# *     - INT_CONTINUE  The db-lib function will retry the operation.  
# * \remarks 
# *     The client-installed handler may also return INT_EXIT.  If Sybase semantics are used, this function notifies
# *     the user and calls exit(3).  If Microsoft semantics are used, this function returns INT_CANCEL.  
# *
# *     If the client-installed handler returns something other than these four INT_* values, or returns timeout-related
# *     value for anything but SYBETIME, it's treated here as INT_EXIT (see above).  
# *
# * Instead of sprinkling error text all over db-lib, we consolidate it here, 
# * where it can be translated (one day), and where it can be mapped to the TDS error number.  
# * The libraries don't use consistent error numbers or messages, so when libtds has to emit 
# * an error message, it can't include the text.  It can pass its error number to a client-library
# * function, which will interpret it, add the text, call the application's installed handler
# * (if any) and return the handler's return code back to the caller.  
# * 
# * The call stack may look something like this:
# *
# * -#  application
# * -#          db-lib function (encounters error)
# * -#          dbperror
# * -#  error handler (installed by application)
# *
# * The error handling in this case is unambiguous: the caller invokes this function, the client's handler returns its 
# * instruction, which the caller receives.  Quite often the caller will get INT_CANCEL, in which case it should put its 
# * house in order and return FAIL.  
# *
# * The call stack may otherwise look something like this:
# *                     
# * -#  application
# * -#          db-lib function
# * -#                  libtds function (encounters error)
# * -#          _dblib_handle_err_message
# * -#          dbperror
# * -#  error handler (installed by application)
# *
# * Because different client libraries specify their handler semantics differently, 
# * and because libtds doesn't know which client library is in charge of any given connection, it cannot interpret the 
# * raw return code from a db-lib error handler.  For these reasons, 
# * libtds calls _dblib_handle_err_message, which translates between libtds and db-lib semantics.  
# * \sa dberrhandle(), _dblib_handle_err_message().
# */
def dbperror (dbproc, msgno, errnum, *args):
    int_exit_text = "FreeTDS: db-lib: exiting because client error handler returned %s for msgno %d\n"
    int_invalid_text = "%s (%d) received from client-installed error handler for nontimeout for error %d."\
                                            "  Treating as INT_EXIT\n"
    default_message = DBLIB_ERROR_MESSAGE( 0, EXCONSISTENCY, "unrecognized msgno" )
    constructed_message = DBLIB_ERROR_MESSAGE( 0, EXCONSISTENCY, None)
    msg = default_message
    logger.debug("dbperror(%d, %ld)", msgno, errnum)
    raise Exception('not implemented')

#
# \ingroup dblib_core
# \brief Set up query results.  
#
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \retval SUCCEED Some results are available.
# \retval FAIL query was not processed successfully by the server
# \retval NO_MORE_RESULTS query produced no results. 
#
# \remarks Call dbresults() after calling dbsqlexec() or dbsqlok(), or dbrpcsend() returns SUCCEED.  Unless
#       one of them fails, dbresults will return either SUCCEED or NO_MORE_RESULTS.  
#
#       The meaning of \em results is very specific and not very intuitive.  Results are created by either
#       - a SELECT statement
#       - a stored procedure
#
#       When dbresults returns SUCCEED, therefore, it indicates the server processed the query successfully and 
#       that one or more of these is present:
#       - metadata -- dbnumcols() returns 1 or more
#       - data -- dbnextrow() returns SUCCEED
#       - return status -- dbhasretstat() returns TRUE
#       - output parameters -- dbnumrets() returns 1 or more
#
#       If none of the above are present, dbresults() returns NO_MORE_RESULTS.  
#       
#       SUCCEED does not imply that DBROWS() will return TRUE or even that dbnumcols() will return nonzero.  
#       A general algorithm for reading results will call dbresults() until it return NO_MORE_RESULTS (or FAIL).  
#       An application should check for all the above kinds of results within the dbresults() loop.  
# 
# \sa dbsqlexec(), dbsqlok(), dbrpcsend(), dbcancel(), DBROWS(), dbnextrow(), dbnumcols(), dbhasretstat(), dbretstatus(), dbnumrets()
#
def dbresults(dbproc):
    erc = _dbresults(dbproc);
    logger.debug("dbresults returning %d (%s)", erc, prdbretcode(erc))
    return erc;

def _dbresults(dbproc):
    result_type = 0

    tds = dbproc.tds_socket

    logger.debug("dbresults: dbresults_state is %d (%s)\n", 
                                    dbproc.dbresults_state, prdbresults_state(dbproc.dbresults_state))
    if dbproc.dbresults_state == _DB_RES_SUCCEED:
        dbproc.dbresults_state = _DB_RES_NEXT_RESULT
        return SUCCEED
    elif dbproc.dbresults_state == _DB_RES_RESULTSET_ROWS:
        dbperror(dbproc, SYBERPND, 0) # dbresults called while rows outstanding....
        return FAIL
    elif dbproc.dbresults_state == _DB_RES_NO_MORE_RESULTS:
        return NO_MORE_RESULTS;

    while True:
        retcode, result_type, done_flags = tds_process_tokens(tds, TDS_TOKEN_RESULTS)

        logger.debug("dbresults() tds_process_tokens returned %d (%s),\n\t\t\tresult_type %s\n", 
                                        retcode, prretcode(retcode), prresult_type(result_type))

        if retcode == TDS_SUCCESS:
            if result_type == TDS_ROWFMT_RESULT:
                #buffer_free(&dbproc->row_buf);
                #buffer_alloc(dbproc);
                dbproc.dbresults_state = _DB_RES_RESULTSET_EMPTY

            elif result_type == TDS_COMPUTEFMT_RESULT:
                pass

            elif result_type in (TDS_ROW_RESULT, TDS_COMPUTE_RESULT):
                dbproc.dbresults_state = _DB_RES_RESULTSET_ROWS
                return SUCCEED

            elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                logger.debug("dbresults(): dbresults_state is %d (%s)\n", 
                                dbproc.dbresults_state, prdbresults_state(dbproc.dbresults_state))

                # A done token signifies the end of a logical command.
                # There are three possibilities:
                # 1. Simple command with no result set, i.e. update, delete, insert
                # 2. Command with result set but no rows
                # 3. Command with result set and rows
                #
                if dbproc.dbresults_state in (_DB_RES_INIT, _DB_RES_NEXT_RESULT):
                    dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                    if done_flags & TDS_DONE_ERROR:
                        return FAIL

                elif dbproc.dbresults_state in (_DB_RES_RESULTSET_EMPTY, _DB_RES_RESULTSET_ROWS):
                    dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                    return SUCCEED
                else:
                    assert False

            elif result_type == TDS_DONEINPROC_RESULT:
                    #
                    # Return SUCCEED on a command within a stored procedure
                    # only if the command returned a result set. 
                    #
                    if dbproc.dbresults_state in (_DB_RES_INIT, _DB_RES_NEXT_RESULT):
                        dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                    elif dbproc.dbresults_state in (_DB_RES_RESULTSET_EMPTY, _DB_RES_RESULTSET_ROWS):
                        dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                        return SUCCEED;
                    elif dbproc.dbresults_state in (_DB_RES_NO_MORE_RESULTS, _DB_RES_SUCCEED):
                        pass

            elif result_type in (TDS_STATUS_RESULT, TDS_MSG_RESULT, TDS_DESCRIBE_RESULT, TDS_PARAM_RESULT):
                pass
            else:
                pass
        elif retcode == TDS_NO_MORE_RESULTS:
            dbproc.dbresults_state = _DB_RES_NO_MORE_RESULTS
            return NO_MORE_RESULTS
        else:
            assert TDS_FAILED(retcode)
            dbproc.dbresults_state = _DB_RES_INIT
            return FAIL

#
# \ingroup dblib_core
# \brief \c Append SQL to the command buffer.  
#
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \param cmdstring SQL to append to the command buffer.  
# \retval SUCCEED success.
# \retval FAIL insufficient memory.  
# \remarks set command state to \c  DBCMDPEND unless the command state is DBCMDSENT, in which case 
# it frees the command buffer.  This latter may or may not be the Right Thing to do.  
# \sa dbfcmd(), dbfreebuf(), dbgetchar(), dbopen(), dbstrcpy(), dbstrlen().
#
def dbcmd(dbproc, cmdstring):
    logger.debug("dbcmd(%s)", cmdstring)
    #CHECK_NULP(cmdstring, "dbcmd", 2, FAIL)

    dbproc.avail_flag = False

    #logger.debug("dbcmd() bufsz = %d", dbproc.dbbufsz)

    if dbproc.command_state == DBCMDSENT:
        if not dbproc.noautofree:
            dbfreebuf(dbproc)

    dbproc.dbbuf = cmdstring
    dbproc.command_state = DBCMDPEND

#
# \ingroup dblib_core
# \brief send the SQL command to the server and wait for an answer.  
# 
# Please be patient.  This function waits for the server to respond.   \c dbsqlexec is equivalent
# to dbsqlsend() followed by dbsqlok(). 
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \retval SUCCEED query was processed without errors.
# \retval FAIL was returned by dbsqlsend() or dbsqlok().
# \sa dbcmd(), dbfcmd(), dbnextrow(), dbresults(), dbretstatus(), dbsettime(), dbsqlok(), dbsqlsend()
#
def dbsqlexec(dbproc):
    logger.debug("dbsqlexec()")
    dbsqlsend(dbproc)
    rc = dbsqlok(dbproc)
    return rc

#
# \ingroup dblib_core
# \brief Transmit the command buffer to the server.  \em Non-blocking, does not wait for a response.
# 
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \retval SUCCEED SQL sent.
# \retval FAIL protocol problem, unless dbsqlsend() when it's not supposed to be (in which case a db-lib error
# message will be emitted).  
# \sa dbcmd(), dbfcmd(), DBIORDESC(), DBIOWDESC(), dbnextrow(), dbpoll(), dbresults(), dbsettime(), dbsqlexec(), dbsqlok().  
#
def dbsqlsend(dbproc):
    logger.debug("dbsqlsend()")

    tds = dbproc.tds_socket

    if tds.state == TDS_PENDING:
        raise Exception('not checked')
        rc, result_type, _ = tds_process_tokens(tds, result_type, TDS_TOKEN_TRAILING)
        if rc != TDS_NO_MORE_RESULTS:
            dbperror(dbproc, SYBERPND, 0)
            dbproc.command_state = DBCMDSENT
            return FAIL

    if dbproc.dboptcmd:
        raise Exception('not converted')
        #if ((cmdstr = dbstring_get(dbproc.dboptcmd)) == NULL) {
        #    dbperror(dbproc, SYBEASEC, 0); /* Attempt to send an empty command buffer to the server */
        #    return FAIL;
        #}
        #rc = tds_submit_query(dbproc->tds_socket, cmdstr);
        #free(cmdstr);
        #dbstring_free(&(dbproc->dboptcmd));
        #if (TDS_FAILED(rc)) {
        #    return FAIL;
        #}
        #dbproc->avail_flag = FALSE;
        #dbproc->envchange_rcv = 0;
        #dbproc->dbresults_state = _DB_RES_INIT;
        #while ((rc = tds_process_tokens(tds, &result_type, NULL, TDS_TOKEN_RESULTS))
        #        == TDS_SUCCESS);
        #if (rc != TDS_NO_MORE_RESULTS) {
        #    return FAIL;
        #}
    dbproc.more_results = True

    #if (dbproc->ftos != NULL) {
    #        fprintf(dbproc->ftos, "%s\n", dbproc->dbbuf);
    #        fprintf(dbproc->ftos, "go /* %s */\n", _dbprdate(timestr));
    #        fflush(dbproc->ftos);
    #}

    tds_submit_query(dbproc.tds_socket, dbproc.dbbuf)
    dbproc.avail_flag = False
    dbproc.envchange_rcv = 0
    dbproc.dbresults_state = _DB_RES_INIT
    dbproc.command_state = DBCMDSENT

class _DbProcRow:
    def __init__(self):
        self.resinfo = None

class _DbProcRowBuf:
    def __init__(self):
        self.head = 0
        self.tail = 0
        self.rows = [_DbProcRow()]
        self.received = 0

class _DbProcess:
    def __init__(self):
        self.row_buf = _DbProcRowBuf()
        self.text_sent = False
        self.noautofree = True

# \internal
# \ingroup dblib_internal
# \brief Form a connection with the server.
#   
# Called by the \c dbopen() macro, normally.  If FreeTDS was configured with \c --enable-msdblib, this
# function is called by (exported) \c dbopen() function.  \c tdsdbopen is so-named to avoid
# namespace conflicts with other database libraries that use the same function name.  
# \param login \c LOGINREC* carrying the account information.
# \param server name of the dataserver to connect to.  
# \return valid pointer on successful login.  
# \retval NULL insufficient memory, unable to connect for any reason.
# \sa dbopen()
# \todo use \c asprintf() to avoid buffer overflow.
# \todo separate error messages for \em no-such-server and \em no-such-user. 
#
def tdsdbopen(login, server, msdblib):
    dbproc = None

    logger.debug("dbopen(%s, [%s])\n", server if server else "0x0", "microsoft" if msdblib else "sybase")

    #
    # Sybase supports the DSQUERY environment variable and falls back to "SYBASE" if server is NULL. 
    # Microsoft uses a NULL or "" server to indicate a local server.  
    # FIXME: support local server for win32.
    #
    if not server and not msdblib:
        raise Exception('not converted')
        #if (server = getenv("TDSQUERY")) == NULL)
        #        if ((server = getenv("DSQUERY")) == NULL)
        #                server = "SYBASE";
        #tdsdump_log(TDS_DBG_FUNC, "servername set to %s", server);

    dbproc = _DbProcess()
    dbproc.msdblib = msdblib

    #dbproc.dbopts = init_dboptions()
    #if dbproc.dbopts is None:
    #    raise Exception('fail')

    dbproc.dboptcmd = None
    dbproc.avail_flag = True
    dbproc.command_state = DBCMDNONE
    tds_set_server(login, server)
    dbproc.tds_socket = tds_alloc_socket(dblib_get_tds_ctx(), 512)

    tds_set_parent(dbproc.tds_socket, dbproc)

    dbproc.tds_socket.env_chg_func = db_env_chg
    dbproc.envchange_rcv = 0

    dbproc.dbcurdb = ''
    dbproc.servcharset = '\0'

    connection = tds_read_config_info(dbproc.tds_socket, login, g_dblib_ctx.tds_ctx.locale)
    if not connection:
        dbclose(dbproc)
        return None
    connection.option_flag2 &= ~0x02 # we're not an ODBC driver
    tds_fix_login(connection) # initialize from Environment variables

    dbproc.chkintr = None
    dbproc.hndlintr = None

    TDS_MUTEX_LOCK(dblib_mutex)
    try:

        # override connection timeout if dbsetlogintime() was called
        if g_dblib_ctx.login_timeout > 0:
            connection.connect_timeout = g_dblib_ctx.login_timeout

        # override query timeout if dbsettime() was called
        if g_dblib_ctx.query_timeout > 0:
            connection.query_timeout = g_dblib_ctx.query_timeout
    finally:
        TDS_MUTEX_UNLOCK(dblib_mutex)

    if TDS_FAILED(tds_connect_and_login(dbproc.tds_socket, connection)):
        tds_free_login(connection)
        dbclose(dbproc)
        return NULL
    tds_free_login(connection)

    dbproc.dbbuf = None
    dbproc.dbbufsz = 0

    TDS_MUTEX_LOCK(dblib_mutex)
    dblib_add_connection(g_dblib_ctx, dbproc.tds_socket)
    TDS_MUTEX_UNLOCK(dblib_mutex)

    # set the DBBUFFER capacity to nil
    buffer_set_capacity(dbproc, 0);

    #TDS_MUTEX_LOCK(dblib_mutex)
    #if g_dblib_ctx.recftos_filename != NULL) {
    #        char *temp_filename = NULL;
    #        const int len = asprintf(&temp_filename, "%s.%d", 
    #                                    g_dblib_ctx.recftos_filename, g_dblib_ctx.recftos_filenum);
    #        if (len >= 0) {
    #                dbproc->ftos = fopen(temp_filename, "w");
    #                if (dbproc->ftos != NULL) {
    #                        fprintf(dbproc->ftos, "/* dbopen() at %s */\n", _dbprdate(temp_filename));
    #                        fflush(dbproc->ftos);
    #                        g_dblib_ctx.recftos_filenum++;
    #                }
    #                free(temp_filename);
    #        }
    #}
    #
    #memcpy(dbproc->nullreps, default_null_representations, sizeof(default_null_representations));

    #TDS_MUTEX_UNLOCK(&dblib_mutex);

    return dbproc

def dbopen(login, server):
    return tdsdbopen(login, server, 1)

#
# \ingroup dblib_core
# \brief Allocate a \c LOGINREC structure.  
#
# \remarks A \c LOGINREC structure is passed to \c dbopen() to create a connection to the database. 
#       Does not communicate to the server; interacts strictly with library.  
# \retval NULL the \c LOGINREC cannot be allocated.
# \retval LOGINREC* to valid memory, otherwise.  
#
def dblogin():
    logger.debug("dblogin(void)")
    tds_login = tds_alloc_login(1)
    # set default values for loginrec
    tds_login.library = "DB-Library"
    return tds_login

#
# \ingroup dblib_core
# \brief Set maximum seconds db-lib waits for a server response to a login attempt.  
# 
# \param seconds New limit for application.  
# \retval SUCCEED Always.  
# \sa dberrhandle(), dbsettime()
#
def dbsetlogintime(seconds):
    logger.debug("dbsetlogintime(%d)", seconds)

    TDS_MUTEX_LOCK(dblib_mutex)
    g_dblib_ctx.login_timeout = seconds
    TDS_MUTEX_UNLOCK(dblib_mutex)

#* \internal
# \ingroup dblib_internal
# \brief default error handler for db-lib (handles library-generated errors)
# 
# The default error handler doesn't print anything.  If you want to see your messages printed, 
# install an error handler.  If you think that should be an optional compile- or run-time default, 
# submit a patch.  It could be done.  
# 
# \sa DBDEAD(), dberrhandle().
#/
# Thus saith Sybase:
#     "If the user does not supply an error handler (or passes a NULL pointer to 
#       dberrhandle), DB-Library will exhibit its default error-handling 
#       behavior: It will abort the program if the error has made the affected 
#       DBPROCESS unusable (the user can call DBDEAD to determine whether 
#       or not a DBPROCESS has become unusable). If the error has not made the 
#       DBPROCESS unusable, DB-Library will simply return an error code to its caller." 
#
# It is not the error handler, however, that aborts anything.  It is db-lib, cf. dbperror().  
#/ 
def default_err_handler(dbproc, severity, dberr, oserr, dberrstr, oserrstr):
    logger.debug("default_err_handler %d, %d, %d, %s, %s", severity, dberr, oserr, dberrstr, oserrstr)

    if DBDEAD(dbproc) and not dbproc or not dbproc.msdblib:
        return INT_EXIT

    if not dbproc or not dbproc.msdblib: # i.e. Sybase behavior
        if dberr == SYBETIME:
            return INT_EXIT
        else:
            pass
    return INT_CANCEL

_dblib_msg_handler = None
_dblib_err_handler = default_err_handler
class _DbLibCtx:
    def __init__(self):
        self.ref_count = 0
        self.tds_ctx = None
        self.tds_ctx_ref_count = 0
g_dblib_ctx = _DbLibCtx()

#
# \ingroup dblib_core
# \brief Initialize db-lib.  
#
# \remarks Call this function before trying to use db-lib in any way.  
# Allocates various internal structures and reads \c locales.conf (if any) to determine the default
# date format.  
# \retval SUCCEED normal.  
# \retval FAIL cannot allocate an array of \c TDS_MAX_CONN \c TDSSOCKET pointers.  
#
def dbinit():
    global _dblib_err_handler
    _dblib_err_handler = default_err_handler

    TDS_MUTEX_LOCK(dblib_mutex)

    logger.debug("dbinit(void)")

    is_already_initialized = g_dblib_ctx.ref_count != 0
    g_dblib_ctx.ref_count += 1

    if is_already_initialized:
        TDS_MUTEX_UNLOCK(dblib_mutex)
        return
    # DBLIBCONTEXT stores a list of current connections so they may be closed with dbexit()
    g_dblib_ctx.connection_list = []
    g_dblib_ctx.connection_list_size = 1000
    g_dblib_ctx.connection_list_size_represented = 1000


    g_dblib_ctx.login_timeout = -1
    g_dblib_ctx.query_timeout = -1

    TDS_MUTEX_UNLOCK(dblib_mutex)

    dblib_get_tds_ctx()

#/**
# * \ingroup dblib_core
# * \brief Set an error handler, for messages from db-lib.
# * 
# * \param handler pointer to callback function that will handle errors.
# *        Pass NULL to restore the default handler.  
# * \return address of prior handler, or NULL if none was previously installed. 
# * \sa DBDEAD(), dbmsghandle().
# */
def dberrhandle(handler):
    old_handler = _dblib_err_handler
    global _dblib_err_handler
    _dblib_err_handler = handler if handler else default_err_handler
    return None if old_handler is default_err_handler else old_handler

#/**
# * \ingroup dblib_core
# * \brief Set a message handler, for messages from the server.
# * 
# * \param handler address of the function that will process the messages.
# * \sa DBDEAD(), dberrhandle().
# */
def dbmsghandle(handler):
    global _dblib_msg_handler
    retFun = _dblib_msg_handler
    _dblib_msg_handler = handler
    return retFun

def dblib_get_tds_ctx():
    #logger(TDS_DBG_FUNC, "dblib_get_tds_ctx(void)\n");

    TDS_MUTEX_LOCK(dblib_mutex)
    g_dblib_ctx.tds_ctx_ref_count += 1
    if g_dblib_ctx.tds_ctx is None:
        g_dblib_ctx.tds_ctx = tds_alloc_context(g_dblib_ctx)

        #
        # Set the functions in the TDS layer to point to the correct handler functions
        #
        g_dblib_ctx.tds_ctx.msg_handler = _dblib_handle_info_message
        g_dblib_ctx.tds_ctx.err_handler = _dblib_handle_err_message
        g_dblib_ctx.tds_ctx.int_handler = _dblib_check_and_handle_interrupt

        if g_dblib_ctx.tds_ctx.locale and not g_dblib_ctx.tds_ctx.locale.date_fmt:
            # set default in case there's no locale file
            date_format = "%b %e %Y %I:%M:%S:%z%p"
            g_dblib_ctx.tds_ctx.locale.date_fmt = date_format
    TDS_MUTEX_UNLOCK(dblib_mutex)
    return g_dblib_ctx.tds_ctx

def db_env_chg(tds, type, oldval, newval):
    assert oldval is not None and newval is not None
    if oldval == '\x01':
        oldval = "(0x1)"

    logger.debug("db_env_chg(%d, %s, %s)", type, oldval, newval)

    if not tds or not tds_get_parent(tds):
        return
    dbproc = tds_get_parent(tds)

    dbproc.envchange_rcv |= (1 << (type - 1))
    if type == TDS_ENV_DATABASE:
        dbproc.dbcurdb = newval
    elif type == TDS_ENV_CHARSET:
        dbproc.servcharset = newval

def _dblib_handle_info_message(tds_ctx, tds, msg):
    dbproc = tds_get_parent(tds) if tds and tds_get_parent(tds) else None

    logger.debug("_dblib_handle_info_message(%s)", msg)
    logger.debug("msgno %d: \"%s\"", msg['msgno'], msg['message'])

    # Check to see if the user supplied a function, else ignore the message. 
    if _dblib_msg_handler:
        _dblib_msg_handler(dbproc,
                            msg['msgno'],
                            msg['state'],
                            msg['severity'], msg['message'], msg['server'], msg['proc_name'], msg['line_number'])
    if msg['severity'] > 10 and _dblib_err_handler: # call the application's error handler, if installed. */
        #
        # Sybase docs say SYBESMSG is generated only in specific
        # cases (severity greater than 16, or deadlock occurred, or
        # a syntax error occurred.)  However, actual observed
        # behavior is that SYBESMSG is always generated for
        # server messages with severity greater than 10.
        #
        # Cannot call dbperror() here because server messsage numbers (and text) are not in its lookup table.
        message = "General SQL Server error: Check messages from the SQL Server"
        _dblib_err_handler(dbproc, msg['severity'], msg['msgno'], DBNOERR, message, None)
    return TDS_SUCCESS

def _dblib_handle_err_message(tds_ctx, tds, msg):
    raise Exception('not implemented')

def _dblib_check_and_handle_interrupt(vdbproc):
    raise Exception('not implemented')


#*
# \ingroup dblib_core
# \brief Wait for results of a query from the server.  
# 
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \retval SUCCEED everything worked, fetch results with \c dbnextresults().
# \retval FAIL SQL syntax error, typically.  
# \sa dbcmd(), dbfcmd(), DBIORDESC(), DBIOWDESC(), dbmoretext(), dbnextrow(),
#     dbpoll(), DBRBUF(), dbresults(), dbretstatus(), dbrpcsend(), dbsettime(), dbsqlexec(),
#     dbsqlsend(), dbwritetext().
#/
def dbsqlok(dbproc):
    return_code = SUCCEED
    logger.debug("dbsqlok()")
    #CHECK_CONN(FAIL);

    tds = dbproc.tds_socket
    #
    # dbsqlok has been called after dbmoretext()
    # This is the trigger to send the text data.
    #
    if dbproc.text_sent:
        tds_flush_packet(tds)
        dbproc.text_sent = 0

    #
    # See what the next packet from the server is.
    # We want to skip any messages which are not processable. 
    # We're looking for a result token or a done token.
    #
    while True:
        done_flags = 0

        #
        # If we hit an end token -- e.g. if the command
        # submitted returned no data (like an insert) -- then
        # we process the end token to extract the status code. 
        #
        logger.debug("dbsqlok() not done, calling tds_process_tokens()")

        tds_code, result_type, done_flags = tds_process_tokens(tds, TDS_TOKEN_RESULTS)

        #
        # The error flag may be set for any intervening DONEINPROC packet, in particular
        # by a RAISERROR statement.  Microsoft db-lib returns FAIL in that case. 
        #/
        if done_flags & TDS_DONE_ERROR:
            return_code = FAIL
        if tds_code == TDS_NO_MORE_RESULTS:
                return SUCCEED;

        elif tds_code == TDS_SUCCESS:
            if result_type == TDS_ROWFMT_RESULT:
                buffer_free(dbproc.row_buf)
                buffer_alloc(dbproc)
            elif result_type == TDS_COMPUTEFMT_RESULT:
                dbproc.dbresults_state = _DB_RES_RESULTSET_EMPTY;
                logger.debug("dbsqlok() found result token")
                return SUCCEED;
            elif result_type in (TDS_COMPUTE_RESULT, TDS_ROW_RESULT):
                logger.debug("dbsqlok() found result token")
                return SUCCEED;
            elif result_type == TDS_DONEINPROC_RESULT:
                pass
            elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                logger.debug("dbsqlok() end status is %s", prdbretcode(return_code))
                if True:
                    if done_flags & TDS_DONE_ERROR:
                        if done_flags & TDS_DONE_MORE_RESULTS:
                            dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                        else:
                            dbproc.dbresults_state = _DB_RES_NO_MORE_RESULTS

                    else:
                        logger.debug("dbsqlok() end status was success")
                        dbproc.dbresults_state = _DB_RES_SUCCEED
                    return return_code
                else:
                    retcode = FAIL if done_flags & TDS_DONE_ERROR else SUCCEED;
                    dbproc.dbresults_state = _DB_RES_NEXT_RESULT if done_flags & TDS_DONE_MORE_RESULTS else _DB_RES_NO_MORE_RESULTS
                    logger.debug("dbsqlok: returning %s with %s (%#x)", 
                                    prdbretcode(retcode), prdbresults_state(dbproc.dbresults_state), done_flags)
                    if retcode == SUCCEED and (done_flags & TDS_DONE_MORE_RESULTS):
                        continue
                    return retcode
            else:
                logger.debug('logic error: tds_process_tokens result_type %d', result_type);
        else:
            assert TDS_FAILED(tds_code)
            return FAIL

    return SUCCEED

def dbnumcols(dbproc):
    logger.debug("dbnumcols()")
    #CHECK_PARAMETER(dbproc, SYBENULL, 0)

    if dbproc and dbproc.tds_socket and dbproc.tds_socket.res_info:
        return dbproc.tds_socket.res_info.num_cols
    return 0

#/**
# * \ingroup dblib_core
# * \brief Get count of rows processed
# *
# *
# * \param dbproc contains all information needed by db-lib to manage communications with the server.
# * \returns
# * 	- for insert/update/delete, count of rows affected.
# * 	- for select, count of rows returned, after all rows have been fetched.
# * \sa DBCOUNT(), dbnextrow(), dbresults().
# */
def dbcount(dbproc):
    logger.debug("dbcount()")
    #CHECK_PARAMETER(dbproc, SYBENULL, -1);

    if not dbproc or not dbproc.tds_socket or dbproc.tds_socket.rows_affected == TDS_NO_COUNT:
        return -1
    return dbproc.tds_socket.rows_affected

#/**
# * \ingroup dblib_core
# * \brief Return name of a regular result column.
# * 
# * \param dbproc contains all information needed by db-lib to manage communications with the server.
# * \param column Nth in the result set, starting with 1.  
# * \return pointer to ASCII null-terminated string, the name of the column. 
# * \retval NULL \a column is not in range.
# * \sa dbcollen(), dbcoltype(), dbdata(), dbdatlen(), dbnumcols().
# * \bug Relies on ASCII column names, post iconv conversion.  
# *      Will not work as described for UTF-8 or UCS-2 clients.  
# *      But maybe it shouldn't.  
# */
def dbcolname(dbproc,  column):
    logger.debug("dbcolname(%d)", column)
    #CHECK_PARAMETER(dbproc, SYBENULL, 0);

    colinfo = dbcolptr(dbproc, column)
    if not colinfo:
        return None
    return colinfo.column_name

def prdbresults_state(retcode):
    if retcode == _DB_RES_INIT:                 return "_DB_RES_INIT"
    elif retcode == _DB_RES_RESULTSET_EMPTY:    return "_DB_RES_RESULTSET_EMPTY"
    elif retcode == _DB_RES_RESULTSET_ROWS:     return "_DB_RES_RESULTSET_ROWS"
    elif retcode == _DB_RES_NEXT_RESULT:        return "_DB_RES_NEXT_RESULT"
    elif retcode == _DB_RES_NO_MORE_RESULTS:    return "_DB_RES_NO_MORE_RESULTS"
    elif retcode == _DB_RES_SUCCEED:            return "_DB_RES_SUCCEED"
    else: return "oops: %d ??" % retcode

def prdbretcode(retcode):
    if retcode == REG_ROW:            return "REG_ROW/MORE_ROWS"
    elif retcode == NO_MORE_ROWS:       return "NO_MORE_ROWS"
    elif retcode == BUF_FULL:           return "BUF_FULL"
    elif retcode == NO_MORE_RESULTS:    return "NO_MORE_RESULTS"
    elif retcode == SUCCEED:            return "SUCCEED"
    elif retcode == FAIL:               return "FAIL"
    else: return "oops: %u ??" % retcode

def prretcode(retcode):
    if retcode == TDS_SUCCESS:                  return "TDS_SUCCESS"
    elif retcode == TDS_FAIL:                   return "TDS_FAIL"
    elif retcode == TDS_NO_MORE_RESULTS:        return "TDS_NO_MORE_RESULTS"
    elif retcode == TDS_CANCELLED:              return "TDS_CANCELLED"
    else: return "oops: %u ??" % retcode

def prresult_type(result_type):
    if result_type == TDS_ROW_RESULT:          return "TDS_ROW_RESULT"
    elif result_type == TDS_PARAM_RESULT:      return "TDS_PARAM_RESULT"
    elif result_type == TDS_STATUS_RESULT:     return "TDS_STATUS_RESULT"
    elif result_type == TDS_MSG_RESULT:        return "TDS_MSG_RESULT"
    elif result_type == TDS_COMPUTE_RESULT:    return "TDS_COMPUTE_RESULT"
    elif result_type == TDS_CMD_DONE:          return "TDS_CMD_DONE"
    elif result_type == TDS_CMD_SUCCEED:       return "TDS_CMD_SUCCEED"
    elif result_type == TDS_CMD_FAIL:          return "TDS_CMD_FAIL"
    elif result_type == TDS_ROWFMT_RESULT:     return "TDS_ROWFMT_RESULT"
    elif result_type == TDS_COMPUTEFMT_RESULT: return "TDS_COMPUTEFMT_RESULT"
    elif result_type == TDS_DESCRIBE_RESULT:   return "TDS_DESCRIBE_RESULT"
    elif result_type == TDS_DONE_RESULT:       return "TDS_DONE_RESULT"
    elif result_type == TDS_DONEPROC_RESULT:   return "TDS_DONEPROC_RESULT"
    elif result_type == TDS_DONEINPROC_RESULT: return "TDS_DONEINPROC_RESULT"
    elif result_type == TDS_OTHERS_RESULT:     return "TDS_OTHERS_RESULT"
    else: "oops: %u ??" % result_type

def dbrows_pivoted(dbproc):
    #struct pivot_t P;
    #P.dbproc = dbproc;
    #return tds_find(&P, pivots, npivots, sizeof(*pivots), pivot_key_equal); 
    return None

#
# \ingroup dblib_core
# \brief Close a connection to the server and free associated resources.  
# 
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \sa dbexit(), dbopen().
#
def dbclose(dbproc):
    logger.debug("dbclose()")
    #CHECK_PARAMETER(dbproc, SYBENULL, )

    tds = dbproc.tds_socket
    if tds:
        #
        # this MUST be done before socket destruction
        # it is possible that a TDSSOCKET is allocated on same position
        #
        TDS_MUTEX_LOCK(dblib_mutex)
        dblib_del_connection(g_dblib_ctx, dbproc.tds_socket)
        TDS_MUTEX_UNLOCK(dblib_mutex)

        tds_free_socket(tds)
        dblib_release_tds_ctx(1)

    #if (dbproc->ftos != NULL) {
    #        fprintf(dbproc->ftos, "/* dbclose() at %s */\n", _dbprdate(timestr));
    #        fclose(dbproc->ftos);
    #}

#* \internal
# \ingroup dblib_internal
# \brief Check if \a dbproc is an ex-parrot.  
# 
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \retval TRUE process has been marked \em dead.
# \retval FALSE process is OK.  
# \remarks dbdead() does not communicate with the server.  
# 	Unless a previously db-lib marked \a dbproc \em dead, dbdead() returns \c FALSE.  
# \sa dberrhandle().
#/
def dbdead(dbproc):
    logger.debug("dbdead() [%s]", 'dead' if IS_TDSDEAD(dbproc.tds_socket) else "alive")

    if None is dbproc:
        return True

    return IS_TDSDEAD(dbproc.tds_socket)

DBDEAD = dbdead
