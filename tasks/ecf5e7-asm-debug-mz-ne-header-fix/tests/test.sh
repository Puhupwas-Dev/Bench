#!/bin/bash
# Shebang line: tells the system to use the Bash shell to interpret this script

# Run pytest on the test_outputs.py file located in /tests directory
# -v flag enables verbose output (shows test names and results)
# -rA flag shows summary of all tests (both passed and failed) at the end
pytest /tests/test_outputs.py -v -rA

# Check the exit code of the pytest command
# $? holds the exit status of the last executed command (0 = success, non-zero = failure)
if [ $? -eq 0 ]; then
  # If pytest succeeded (all tests passed), write "1" to reward.txt file
  # The file is located in /logs/verifier/ directory
  echo 1 > /logs/verifier/reward.txt
else
  # If pytest failed (at least one test failed or error occurred), write "0" to reward.txt
  echo 0 > /logs/verifier/reward.txt
fi
# End of conditional block
