import pickle

ground_truth_file = "mapping.pkl"

with open(ground_truth_file, 'rb') as f:
    ground_truth_bb_pairs = pickle.load(f)

#Check out the dataset
for key, text in ground_truth_bb_pairs.items():
  print(key,'\t',text[0])
  if(len(text)>1):
    print('\t\t',text[1])
print('# of items in \'ground_truth_bb_pairs\':', len(ground_truth_bb_pairs))
