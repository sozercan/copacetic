// Test the fixed Copa tag logic

function testCopaTagLogic() {
    const testCases = [
        { image: "nginx:1.27.0", output_tag: "nginx:1.27.0-patched" },
        { image: "nginx:1.27.0", output_tag: "patched" },
        { image: "nginx:1.27.0", output_tag: "-patched" },
        { image: "nginx:1.27.0", output_tag: undefined },
        { image: "nginx", output_tag: "nginx-patched" },
        { image: "ubuntu:20.04", output_tag: "ubuntu:20.04-fixed" },
    ];

    testCases.forEach(({ image, output_tag }) => {
        console.log(`\n--- Test Case ---`);
        console.log(`Input image: ${image}`);
        console.log(`Input output_tag: ${output_tag}`);

        // Simulate the new logic from index.ts
        let outputTag = "-patched"; // Default tag suffix
        let outputImage = output_tag || `${image}-patched`; // For logging/tracking purposes

        if (output_tag) {
          // Extract just the tag part from the full image name
          // e.g., "nginx:1.27.0-patched" -> "-patched"
          const colonIndex = output_tag.lastIndexOf(':');
          if (colonIndex !== -1) {
            const tagPart = output_tag.substring(colonIndex + 1);
            // If the original image has a tag, extract the suffix
            const originalColonIndex = image.lastIndexOf(':');
            if (originalColonIndex !== -1) {
              const originalTag = image.substring(originalColonIndex + 1);
              if (tagPart.startsWith(originalTag)) {
                outputTag = tagPart.substring(originalTag.length);
              } else {
                outputTag = `-${tagPart}`;
              }
            } else {
              outputTag = `-${tagPart}`;
            }
          } else {
            // No colon in output_tag, treat as suffix
            outputTag = output_tag.startsWith('-') ? output_tag : `-${output_tag}`;
          }
        }

        console.log(`Extracted outputTag for Copa: ${outputTag}`);
        console.log(`Copa command would be: copa patch -i ${image} -t ${outputTag}`);
        console.log(`Expected final image name: ${image}${outputTag}`);
    });
}

testCopaTagLogic();
