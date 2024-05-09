# sudo apt install cscope
find ./source/ -maxdepth 2 -name "*.c" -o -name "*.h" > cscope.files
cscope -R -b -i cscope.files
found_invalid_proof_api=0
while read p; do
    out=$(cscope -L1 $p)
    if ! [ -n "$out" ]; then
        echo "No function: " $p " exists."
        found_invalid_proof_api=1
    fi
done <.github/cbmc_function_list.txt

if [ "$found_invalid_proof_api" -eq 1 ]; then
    echo "FAILED"
    exit 1;
else
    echo "SUCCEEDED"
    exit 0;
fi