for dir in */; do
    cd "$dir"
    make clean
    make
    cd ..
done