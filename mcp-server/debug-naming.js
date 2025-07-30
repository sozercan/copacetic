// Debug script to test image name construction logic

function debugImageNaming() {
    // Test the logic from index.ts trigger_remediation case
    const testCases = [
        { image: "nginx:1.27.0", output_tag: "nginx:1.27.0-patched" },
        { image: "nginx:1.27.0", output_tag: undefined },
        { image: "nginx", output_tag: undefined },
        { image: "ubuntu:20.04", output_tag: "ubuntu:20.04-fixed" },
    ];

    testCases.forEach(({ image, output_tag }) => {
        console.log(`\n--- Test Case ---`);
        console.log(`Input image: ${image}`);
        console.log(`Input output_tag: ${output_tag}`);

        // Simulate the logic from index.ts lines 516-528
        let outputImage = output_tag;
        if (!outputImage) {
            // For short names like nginx:1.20, create nginx-patched:1.20 to avoid duplication
            const parts = image.split(':');
            if (parts.length === 2) {
                outputImage = `${parts[0]}-patched:${parts[1]}`;
            } else if (parts.length === 1) {
                outputImage = `${image}-patched:latest`;
            } else {
                outputImage = `${image}-patched`;
            }
        }

        console.log(`Constructed outputImage: ${outputImage}`);
        console.log(`Copa command would be: copa patch -i ${image} -t ${outputImage}`);
    });
}

debugImageNaming();
