parellel_build_cnt = 0

if [ ! $j -eq 0 ]
  then
    parellel_build_cnt = $j
fi

rm -rf ./test/unit-test/build/*
cmake -S test/unit-test -B test/unit-test/build/ -DCMAKE_BUILD_TYPE=Debug
make -C test/unit-test/build/ all -j8
