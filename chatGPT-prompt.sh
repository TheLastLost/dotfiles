#!/bin/bash

# Variables
api_key="YOUR_API_KEY"

echo "Welcome to the OpenAI prompt mode."
echo "Enter 'exit' to leave the prompt mode."

# Loop until user exits
while true; do
    # Get the prompt from the user
    read -p "Enter your prompt: " prompt

    # Exit if the user enters 'exit'
    if [ "$prompt" == "exit" ]; then
        break
    fi

    # Make a POST request to the OpenAI API
    response=$(curl -X POST -H "Content-Type: application/json" 
    -H "Authorization: Bearer $api_key" 
    -d "{\"prompt\":\"$prompt\"}" https://api.openai.com/v1/engines/davinci/completions)

    # Extract the answer from the response
    answer=$(echo $response | jq -r '.choices[0].text')

    # Print the answer
    echo "Answer: $answer"
    echo ""
done
