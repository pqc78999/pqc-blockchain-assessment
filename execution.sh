csv_path="/HOME/30runs_data.csv"

for dir in */; do
    cd "$dir"
    echo >> "$csv_path"
    echo -n "${dir%/}" >> "$csv_path"
    ./PQCgenKAT_sign
    cd ..
done