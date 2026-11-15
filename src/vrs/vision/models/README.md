# Model files

| File | What it is | Source and licence |
|---|---|---|
| `face_detection_yunet_2023mar.onnx` | YuNet face detector used to blur faces before anything is stored | OpenCV Model Zoo (`opencv/opencv_zoo`, `models/face_detection_yunet`), MIT licence |

The vehicle detector and plate reader weights are not shipped. Put them here
when you move to real hardware, then list every model in a signed manifest:

    python scripts/sign_update.py models --key <your signing key> --version <version>

With `updates.require_signed_models: true` the device refuses to start if a
model it is about to load is missing from that manifest or differs from it.
