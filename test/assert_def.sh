#!/bin/sh

success=0
failure=0

function assert() {
    actual=`echo $(./$3 $1)`
    expect=$2
    if [[ $actual == $expect ]]; then
        success=`expr $success + 1`
    else
        failure=`expr $failure + 1`
        echo "failure:"
    fi
    echo actual:$actual expect:$expect
}

function reset_success_failure() {
    success=0
    failure=0
}

function display_test_result() {
    echo success: $success, failure: $failure.
    echo
}
