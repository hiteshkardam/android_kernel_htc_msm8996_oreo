export CROSS_COMPILE=$(pwd)/../aarch64-linux-android-4.9/bin/aarch64-linux-android-
export CROSS_COMPILE_ARM32=$(pwd)/../arm-linux-androideabi-4.9/bin/arm-linux-androideabi-
export ARCH=arm64 && export SUBARCH=arm64

mkdir -p out
#make O=out clean
#make O=out mrproper
make O=out mafia_defconfig
make O=out -j$(nproc --all)