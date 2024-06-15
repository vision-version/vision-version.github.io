from flask import Flask, request, jsonify
from SimilarityService import SimilarityService
app = Flask(__name__)
similarity_service = SimilarityService()

@app.route('/', methods=['GET'])
def root():
    print("calculate_similarity")
    return "calculate_similarity"

@app.route('/calculate_similarity', methods=['GET'])
def calculate_similarity():
    string1 = request.args.get('string1', '')
    string2 = request.args.get('string2', '')

    if not string1 or not string2:
        return jsonify({'error': 'Invalid input'})

    similarity_score = similarity_service.calculate_similarity(string1, string2)
    return jsonify({'similarity_score': similarity_score})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)