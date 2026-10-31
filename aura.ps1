param(
    [Parameter(ValueFromRemainingArguments = $true)]
    $RemainingArgs
)
python -m aura.cli @RemainingArgs

