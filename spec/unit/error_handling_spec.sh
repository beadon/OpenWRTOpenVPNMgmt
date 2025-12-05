# ShellSpec unit tests for error handling functions

# Source the script with test guard enabled
SHELLSPEC_TESTING=true
. ./openvpn_server_management.sh

Describe "Error handling functions"

    Describe "run_cmd()"
        It "returns success when command succeeds"
            When call run_cmd "list files" ls /
            The status should be success
        End

        It "returns failure when command fails"
            When call run_cmd "access nonexistent" ls /nonexistent_path_12345
            The status should be failure
        End

        It "outputs error message to stderr on failure"
            When call run_cmd "access nonexistent" ls /nonexistent_path_12345
            The stderr should include "ERROR: Failed to access nonexistent"
        End

        It "does not output error message on success"
            When call run_cmd "list files" ls /
            The stderr should equal ""
        End
    End

    Describe "error_exit()"
        It "outputs error message to stderr"
            When run error_exit "Something went wrong"
            The stderr should equal "ERROR: Something went wrong"
        End

        It "exits with status 1"
            When run error_exit "Something went wrong"
            The status should equal 1
        End
    End

    Describe "warn()"
        It "outputs warning message to stderr"
            When call warn "This is a warning"
            The stderr should equal "WARNING: This is a warning"
        End

        It "does not exit"
            When call warn "This is a warning"
            The status should be success
        End
    End

    Describe "info()"
        It "outputs info message to stderr"
            When call info "Informational message"
            The stderr should equal "INFO: Informational message"
        End

        It "does not exit"
            When call info "Informational message"
            The status should be success
        End
    End

    Describe "register_temp() and cleanup()"
        setup() {
            TEMP_FILES=""
        }

        cleanup_test() {
            rm -f /tmp/shellspec_test_* 2>/dev/null || true
        }

        BeforeEach 'setup'
        AfterEach 'cleanup_test'

        It "registers temp file to TEMP_FILES variable"
            When call register_temp "/tmp/test_file_1"
            The variable TEMP_FILES should include "/tmp/test_file_1"
        End

        It "cleanup removes registered temp files"
            touch /tmp/shellspec_test_cleanup_1
            touch /tmp/shellspec_test_cleanup_2
            TEMP_FILES="/tmp/shellspec_test_cleanup_1 /tmp/shellspec_test_cleanup_2"

            When call cleanup
            The file "/tmp/shellspec_test_cleanup_1" should not be exist
            The file "/tmp/shellspec_test_cleanup_2" should not be exist
        End
    End
End
