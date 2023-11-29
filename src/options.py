"""Default values for the options / filters"""

# FILTERS #####################################################################

MIN_CONFIDENCE = 0.7 # probability threshold

# STATS #######################################################################

ALERT_HISTORY_SIZE = 2 ** 15 # in number of transactions recorded

# DATABASE ####################################################################

DATABASE_CHUNK_SIZE = 2 ** 10 # number of records in each parquet file
