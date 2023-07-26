#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([NetSniffer], [1.0], [bug-automake@gnu.org])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([CSniffv3.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace 'main' with a function in '-lcrypto':
AC_CHECK_LIB([crypto], [main])
# FIXME: Replace 'main' with a function in '-lncurses':
AC_CHECK_LIB([ncurses], [main])
# FIXME: Replace 'main' with a function in '-lpcap':
AC_CHECK_LIB([pcap], [main])
# FIXME: Replace 'main' with a function in '-lsqlite3':
AC_CHECK_LIB([sqlite3], [main])
# FIXME: Replace 'main' with a function in '-lssl':
AC_CHECK_LIB([ssl], [main])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdint.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([inet_ntoa strchr strcspn strdup strstr strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
